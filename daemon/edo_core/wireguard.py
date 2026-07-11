"""WireGuard control plane for the edo daemon.

Ported near-verbatim from edo's src/wireguard.py — key generation, config
rendering, and live-apply via `wg` are exactly what edo already does well,
and there's no owner/team concept needed on this side: the WireGuard pool
stays edo's original flat 10.8.0.0/24, one peer per CTFd user (never per
team — a team's members each keep their own VPN identity). What ties a
peer to a team for firewall purposes is the owner_type/owner_id columns on
the peer row (see db.py), not the WG topology itself.
"""
from __future__ import annotations

import configparser
import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .db import DatabaseManager, Peer
from .install_hints import install_hint
from .network import WG_INTERFACE, WG_SERVER_IP, WG_SUBNET, ordered_subnet_hosts

logger = logging.getLogger(__name__)

WG_CONFIG_DIR = Path("/etc/wireguard")
WG_SERVER_CONFIG = WG_CONFIG_DIR / f"{WG_INTERFACE}.conf"
WG_CLIENTS_DIR = WG_CONFIG_DIR / "edo_clients"
WG_LISTEN_PORT = 51820

CLIENT_KEY_PLACEHOLDER = "<PASTE_YOUR_PRIVATE_KEY_HERE>"


@dataclass
class KeyPair:
    private_key: str
    public_key: str


@dataclass
class ServerConfig:
    private_key: str
    public_key: str
    endpoint: str
    listen_port: int
    config_path: Path = WG_SERVER_CONFIG


@dataclass
class ClientConfig:
    peer: Peer
    config_text: str
    config_path: Path


@dataclass
class LivePeerStatus:
    public_key: str
    endpoint: Optional[str]
    latest_handshake: int
    rx_bytes: int
    tx_bytes: int

    @property
    def online(self) -> bool:
        if self.latest_handshake == 0:
            return False
        return (time.time() - self.latest_handshake) < 180


def _run(cmd: List[str], stdin: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
    logger.debug("exec: %s", " ".join(cmd))
    try:
        return subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=check)
    except FileNotFoundError as e:
        raise RuntimeError(
            f"required binary not found: {cmd[0]}\n  install: {install_hint(cmd[0])}"
        ) from e


def generate_keypair() -> KeyPair:
    try:
        priv = _run(["wg", "genkey"]).stdout.strip()
        pub = _run(["wg", "pubkey"], stdin=priv).stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"wg key generation failed: {(e.stderr or '').strip()}") from e
    return KeyPair(private_key=priv, public_key=pub)


def _derive_pubkey(private_key: str) -> str:
    try:
        return _run(["wg", "pubkey"], stdin=private_key).stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"wg pubkey failed: {(e.stderr or '').strip()}") from e


def is_valid_wg_key(key: str) -> bool:
    import base64
    key = key.strip()
    if len(key) != 44 or not key.endswith("="):
        return False
    try:
        return len(base64.b64decode(key, validate=True)) == 32
    except ValueError:
        return False


def _peer_candidate_ips() -> List[str]:
    return ordered_subnet_hosts(WG_SUBNET, reserved=[WG_SERVER_IP])


def init_server(endpoint: str, port: int = WG_LISTEN_PORT) -> ServerConfig:
    WG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if WG_SERVER_CONFIG.exists():
        return _load_server_config(endpoint, port)

    kp = generate_keypair()
    contents = (
        "[Interface]\n"
        "# edo: WireGuard server interface\n"
        f"Address = {WG_SERVER_IP}/{WG_SUBNET.prefixlen}\n"
        f"ListenPort = {port}\n"
        f"PrivateKey = {kp.private_key}\n"
        "SaveConfig = false\n"
    )
    WG_SERVER_CONFIG.write_text(contents)
    WG_SERVER_CONFIG.chmod(0o600)
    return ServerConfig(private_key=kp.private_key, public_key=kp.public_key, endpoint=endpoint, listen_port=port)


def _parse_interface_section() -> Dict[str, str]:
    if not WG_SERVER_CONFIG.exists():
        raise RuntimeError(f"{WG_SERVER_CONFIG} does not exist")
    parser = configparser.ConfigParser(
        strict=False, allow_no_value=True,
        comment_prefixes=("#", ";"), inline_comment_prefixes=("#",),
        interpolation=None,
    )
    parser.optionxform = str  # type: ignore[assignment]
    try:
        parser.read(WG_SERVER_CONFIG)
    except configparser.Error as e:
        raise RuntimeError(f"failed to parse {WG_SERVER_CONFIG}: {e}") from e
    if "Interface" not in parser:
        raise RuntimeError(f"no [Interface] section in {WG_SERVER_CONFIG}")
    return {k: (v or "").strip() for k, v in parser["Interface"].items()}


def load_server_config(endpoint: str, port: int) -> ServerConfig:
    """Public entry point — reads the existing server config off disk
    (does not create one; call init_server() first if it might not exist).
    """
    return _load_server_config(endpoint, port)


def _load_server_config(endpoint: str, port: int) -> ServerConfig:
    iface = _parse_interface_section()
    priv = iface.get("PrivateKey", "")
    if not priv:
        raise RuntimeError(f"no PrivateKey in [Interface] of {WG_SERVER_CONFIG}")
    return ServerConfig(private_key=priv, public_key=_derive_pubkey(priv), endpoint=endpoint, listen_port=port)


def get_listen_port() -> int:
    try:
        iface = _parse_interface_section()
    except RuntimeError:
        return WG_LISTEN_PORT
    raw = iface.get("ListenPort", "")
    try:
        return int(raw) if raw else WG_LISTEN_PORT
    except ValueError:
        return WG_LISTEN_PORT


def get_live_peer_status() -> Dict[str, LivePeerStatus]:
    try:
        proc = _run(["wg", "show", WG_INTERFACE, "dump"], check=False)
    except RuntimeError:
        return {}
    if proc.returncode != 0:
        return {}
    out: Dict[str, LivePeerStatus] = {}
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        try:
            handshake, rx, tx = int(parts[4]), int(parts[5]), int(parts[6])
        except ValueError:
            continue
        out[parts[0]] = LivePeerStatus(
            public_key=parts[0],
            endpoint=parts[2] if parts[2] != "(none)" else None,
            latest_handshake=handshake, rx_bytes=rx, tx_bytes=tx,
        )
    return out


def add_peer(
    db: DatabaseManager,
    owner_type: str,
    owner_id: int,
    username: str,
    server: ServerConfig,
    clients_dir: Optional[Path] = None,
    public_key: Optional[str] = None,
) -> ClientConfig:
    """Allocate, persist, write, and live-apply a new peer.

    See edo's original add_peer for the two key-handling modes (server-side
    vs client-side keys) — unchanged here. owner_type/owner_id are new:
    they tag the peer for the firewall rule builder in network.py.
    """
    if public_key is not None:
        public_key = public_key.strip()
        if not is_valid_wg_key(public_key):
            raise ValueError(f"'{public_key}' is not a valid WireGuard public key")
        stored_public, stored_private = public_key, None
    else:
        kp = generate_keypair()
        stored_public, stored_private = kp.public_key, kp.private_key

    peer = db.allocate_peer(
        owner_type=owner_type, owner_id=owner_id, username=username,
        public_key=stored_public, private_key=stored_private,
        candidate_ips=_peer_candidate_ips(),
    )

    out_dir = Path(clients_dir) if clients_dir is not None else WG_CLIENTS_DIR
    try:
        _append_peer_to_server_config(peer)
        _live_add_peer(peer)
        client_text = _render_client_config(peer, server)
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            out_dir.chmod(0o700)
        except OSError:
            pass
        out_path = out_dir / f"{username}.conf"
        out_path.write_text(client_text)
        out_path.chmod(0o600)
    except Exception:
        logger.exception("peer creation failed for %s, rolling back DB", username)
        db.remove_peer(username)
        raise

    return ClientConfig(peer=peer, config_text=client_text, config_path=out_path)


def remove_peer(db: DatabaseManager, username: str, clients_dir: Optional[Path] = None) -> bool:
    peer = db.get_peer(username)
    if not peer:
        return False
    try:
        _run(["wg", "set", WG_INTERFACE, "peer", peer.public_key, "remove"])
    except subprocess.CalledProcessError as e:
        logger.warning("live peer removal for %s failed: %s", username, (e.stderr or "").strip())

    _rewrite_server_config(db, exclude_username=username)
    db.remove_peer(username)

    out_dir = Path(clients_dir) if clients_dir is not None else WG_CLIENTS_DIR
    client_conf = out_dir / f"{username}.conf"
    if client_conf.exists():
        client_conf.unlink()
    return True


def _append_peer_to_server_config(peer: Peer) -> None:
    block = f"\n[Peer]\n# {peer.username}\nPublicKey = {peer.public_key}\nAllowedIPs = {peer.ip_address}/32\n"
    with WG_SERVER_CONFIG.open("a") as f:
        f.write(block)


def _rewrite_server_config(db: DatabaseManager, exclude_username: str) -> None:
    text = WG_SERVER_CONFIG.read_text()
    header = text.split("[Peer]", 1)[0].rstrip() + "\n"
    parts = [header]
    for p in db.get_all_peers():
        if p.username == exclude_username:
            continue
        parts.append(f"\n[Peer]\n# {p.username}\nPublicKey = {p.public_key}\nAllowedIPs = {p.ip_address}/32\n")
    WG_SERVER_CONFIG.write_text("".join(parts))


def render_client_config(peer: Peer, server: ServerConfig) -> str:
    """Public entry point for the daemon's wg.render_config RPC."""
    return _render_client_config(peer, server)


def _render_client_config(peer: Peer, server: ServerConfig) -> str:
    from .network import DOCKER_POOL

    if peer.private_key:
        priv_line = f"PrivateKey = {peer.private_key}\n"
        note = ""
    else:
        priv_line = f"PrivateKey = {CLIENT_KEY_PLACEHOLDER}\n"
        note = "# NOTE: replace the PrivateKey placeholder below with your own private key.\n"
    return (
        "[Interface]\n"
        f"# edo: client config for {peer.username}\n"
        f"{note}{priv_line}"
        f"Address = {peer.ip_address}/32\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        f"PublicKey = {server.public_key}\n"
        f"Endpoint = {server.endpoint}:{server.listen_port}\n"
        f"AllowedIPs = {WG_SUBNET}, {DOCKER_POOL}\n"
        "PersistentKeepalive = 25\n"
    )


def _live_add_peer(peer: Peer) -> None:
    try:
        _run(["wg", "set", WG_INTERFACE, "peer", peer.public_key, "allowed-ips", f"{peer.ip_address}/32"])
    except subprocess.CalledProcessError as e:
        logger.warning("could not apply peer to live %s: %s", WG_INTERFACE, (e.stderr or "").strip())


def bring_up() -> None:
    try:
        _run(["wg-quick", "up", WG_INTERFACE])
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").lower()
        if "already exists" in stderr or "rtnetlink" in stderr:
            return
        raise RuntimeError(f"wg-quick up {WG_INTERFACE} failed: {(e.stderr or '').strip()}") from e


def bring_down() -> None:
    try:
        _run(["wg-quick", "down", WG_INTERFACE])
    except subprocess.CalledProcessError as e:
        logger.warning("wg-quick down %s: %s", WG_INTERFACE, (e.stderr or "").strip())


def reload_interface() -> None:
    bring_down()
    bring_up()
