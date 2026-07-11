#!/usr/bin/env python3
"""
edo-daemon: root-privileged sidecar for the CTFd edo-plugin.

Runs as `root` on the CTF host, listens on a filesystem-permissioned Unix
socket, and executes the actions the unprivileged CTFd worker can't:
    - WireGuard peer allocation / revocation
    - Docker container spawn / teardown into a per-team-isolated bridge
    - iptables rules enforcing "Team A cannot reach Team B" micro-segmentation

This file is a SKELETON. The pure Python bits (framing, HMAC verification,
dispatch table, config allocator) are implemented; the shell-outs to
`wg`, `docker`, and `iptables` are stubbed with clearly marked TODOs and
the exact commands you'd run.

Dependencies: python3-only stdlib. No Flask/FastAPI needed for a JSON RPC
this small, and it keeps the root process's dependency surface minimal.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from hmac import compare_digest, new as hmac_new
from hashlib import sha256
from pathlib import Path

# ---------- Config (env-driven) ----------

SOCKET_PATH = os.environ.get("EDO_DAEMON_SOCKET", "/run/edo/edo-daemon.sock")
HMAC_KEY    = os.environ.get("EDO_DAEMON_HMAC_KEY", "").encode()
STATE_FILE  = Path(os.environ.get("EDO_DAEMON_STATE", "/var/lib/edo/state.json"))
VPN_SUBNET  = os.environ.get("EDO_VPN_SUBNET", "10.9.0.0/24")
VPN_ENDPOINT = os.environ.get("EDO_VPN_ENDPOINT", "vpn.example.com:51820")
WG_INTERFACE = os.environ.get("EDO_WG_INTERFACE", "wg0")
DOCKER_NETWORK_PREFIX = os.environ.get("EDO_DOCKER_NET", "edo_team_")

# The socket is chmod 0660 and chown root:ctfd so ONLY the CTFd user
# can talk to us — HMAC is defence-in-depth.
SOCKET_MODE  = 0o660
SOCKET_OWNER = os.environ.get("EDO_SOCKET_OWNER", "root:ctfd")

MAX_REPLAY_WINDOW = 30  # seconds — reject requests whose ts is too old

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("edo-daemon")


# ---------- Persistent state ----------
# Minimal on-disk state so we survive restarts. For real deployments swap
# for SQLite. We hold the write lock while mutating.

_state_lock = threading.Lock()

def _load_state() -> dict:
    if not STATE_FILE.exists():
        return {"wg_peers": {}, "containers": {}, "team_bridges": {}}
    try:
        return json.loads(STATE_FILE.read_text())
    except json.JSONDecodeError:
        log.exception("state file corrupt, starting fresh")
        return {"wg_peers": {}, "containers": {}, "team_bridges": {}}

def _save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(STATE_FILE)


# ---------- WireGuard ----------

def _next_free_ip(state: dict) -> str:
    """Allocate the next unused address inside VPN_SUBNET."""
    net = ipaddress.ip_network(VPN_SUBNET)
    used = {p["assigned_ip"] for p in state["wg_peers"].values()}
    # .1 reserved for server; skip network + broadcast.
    for host in net.hosts():
        h = str(host)
        if h == str(next(net.hosts())):  # server IP
            continue
        if h not in used:
            return h
    raise RuntimeError("VPN subnet exhausted")


def _wg_generate_keypair() -> tuple[str, str]:
    """
    Generate a WireGuard keypair using the wg tool.

    TODO: swap for the `nacl` bindings if you don't want to shell out.
    """
    priv = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pub  = subprocess.check_output(["wg", "pubkey"], input=priv.encode()).decode().strip()
    return priv, pub


def _wg_server_pubkey() -> str:
    """
    Read the server's public key. Cached in state; regenerate if missing.
    """
    # Convention: server private is at /etc/wireguard/{iface}.key
    priv_path = Path(f"/etc/wireguard/{WG_INTERFACE}.key")
    priv = priv_path.read_text().strip()
    return subprocess.check_output(["wg", "pubkey"], input=priv.encode()).decode().strip()


def handle_wg_generate_peer(params: dict) -> dict:
    user_id = int(params["user_id"])
    team_id = params.get("team_id")

    with _state_lock:
        state = _load_state()
        # Idempotent: return the existing peer if user already has one.
        for peer in state["wg_peers"].values():
            if peer["user_id"] == user_id and not peer.get("revoked"):
                return peer

        priv, pub = _wg_generate_keypair()
        ip = _next_free_ip(state)

        peer = {
            "user_id":     user_id,
            "team_id":     team_id,
            "public_key":  pub,
            "private_key": priv,   # stored so plugin can re-render config
            "assigned_ip": ip,
            "created_at":  int(time.time()),
            "revoked":     False,
        }
        state["wg_peers"][pub] = peer
        _save_state(state)

    # TODO: add peer live via `wg set` so it works without wg-quick reload.
    # allowed = f"{ip}/32"
    # subprocess.check_call([
    #     "wg", "set", WG_INTERFACE,
    #     "peer", pub, "allowed-ips", allowed,
    # ])

    peer_out = dict(peer)
    peer_out["server_public_key"] = _wg_server_pubkey()
    peer_out["endpoint"]     = VPN_ENDPOINT
    peer_out["allowed_ips"]  = VPN_SUBNET
    peer_out["dns"]          = "10.9.0.1"
    return peer_out


def handle_wg_revoke_peer(params: dict) -> dict:
    pub = params["public_key"]
    with _state_lock:
        state = _load_state()
        peer = state["wg_peers"].get(pub)
        if not peer:
            raise KeyError("unknown peer")
        peer["revoked"] = True
        _save_state(state)
    # TODO: subprocess.check_call(["wg", "set", WG_INTERFACE, "peer", pub, "remove"])
    return {"revoked": pub}


def handle_wg_render_config(params: dict) -> str:
    peer = params["peer"]
    server_pub = _wg_server_pubkey()
    ip = peer["assigned_ip"]
    return (
        "[Interface]\n"
        f"PrivateKey = {peer['private_key']}\n"
        f"Address    = {ip}/32\n"
        "DNS        = 10.9.0.1\n\n"
        "[Peer]\n"
        f"PublicKey  = {server_pub}\n"
        f"Endpoint   = {VPN_ENDPOINT}\n"
        f"AllowedIPs = {VPN_SUBNET}\n"
        "PersistentKeepalive = 25\n"
    )


# ---------- Docker + iptables ----------

def _ensure_team_bridge(team_id: int | None) -> str:
    """
    Create a Docker bridge dedicated to a team if one doesn't exist yet.

    The team subnet is derived deterministically from team_id so restarts
    yield the same layout. Returns the bridge name.
    """
    if team_id is None:
        return "bridge"  # solo/user mode falls back to default
    name = f"{DOCKER_NETWORK_PREFIX}{team_id}"
    with _state_lock:
        state = _load_state()
        if name in state["team_bridges"]:
            return name
        # /28 per team gives 14 usable addresses — enough for a handful of
        # simultaneous containers per team. Adjust to taste.
        base = ipaddress.ip_network("172.30.0.0/16")
        subnet = list(base.subnets(new_prefix=28))[team_id % 4096]
        state["team_bridges"][name] = str(subnet)
        _save_state(state)

    # TODO: create the docker network + iptables isolation:
    # subprocess.check_call([
    #     "docker", "network", "create",
    #     "--driver", "bridge",
    #     "--subnet", str(subnet),
    #     "--opt", "com.docker.network.bridge.enable_icc=true",
    #     name,
    # ])
    # _install_isolation_rules(name, str(subnet))
    return name


def _install_isolation_rules(bridge: str, subnet: str) -> None:
    """
    Enforce: containers in `bridge` can reach the internet and the VPN
    subnet, but CANNOT reach any other edo_team_* subnet.

    We chain-scope our rules under EDO_TEAM_ISOLATION so we can flush
    without touching operator rules.

    TODO: implement — this is the sketch:
        iptables -N EDO_TEAM_ISOLATION 2>/dev/null || true
        iptables -I FORWARD -j EDO_TEAM_ISOLATION
        iptables -A EDO_TEAM_ISOLATION -s <subnet> -d 172.30.0.0/16 -j DROP
        iptables -A EDO_TEAM_ISOLATION -s 172.30.0.0/16 -d <subnet> -j DROP
        # Allow VPN -> this team's containers (participants reach their box):
        iptables -A EDO_TEAM_ISOLATION -s <vpn_subnet> -d <subnet> -j ACCEPT
    """
    pass


def handle_container_spawn(params: dict) -> dict:
    challenge_id  = params["challenge_id"]
    team_id       = params.get("team_id")
    user_id       = params.get("user_id")
    image         = params["image"]
    exposed_ports = params.get("exposed_ports") or []
    cpu_limit     = float(params.get("cpu_limit") or 1.0)
    memory_mb     = int(params.get("memory_mb") or 512)
    pids_limit    = int(params.get("pids_limit") or 256)
    ttl_seconds   = int(params.get("ttl_seconds") or 3600)

    network = _ensure_team_bridge(team_id)
    name = f"edo_c{challenge_id}_t{team_id or 'u'}_{user_id or 'x'}_{int(time.time())}"

    # TODO: actually run docker. Sketch:
    # cmd = [
    #     "docker", "run", "-d", "--rm",
    #     "--name", name,
    #     "--network", network,
    #     "--cpus", str(cpu_limit),
    #     "--memory", f"{memory_mb}m",
    #     "--pids-limit", str(pids_limit),
    #     "--cap-drop", "ALL",
    #     "--security-opt", "no-new-privileges:true",
    #     "--read-only",
    # ]
    # for p in exposed_ports:
    #     cmd += ["-p", p]
    # cmd += [image]
    # container_id = subprocess.check_output(cmd).decode().strip()
    # meta = subprocess.check_output([
    #     "docker", "inspect", container_id,
    #     "--format", "{{json .NetworkSettings}}"
    # ])
    container_id = f"stub_{name}"
    host_ip = "10.9.0.1"
    host_ports = ",".join(exposed_ports) if exposed_ports else ""

    with _state_lock:
        state = _load_state()
        state["containers"][container_id] = {
            "container_id": container_id,
            "container_name": name,
            "challenge_id": challenge_id,
            "team_id": team_id,
            "user_id": user_id,
            "status": "running",
            "host_ip": host_ip,
            "host_ports": host_ports,
            "expires_at": int(time.time()) + ttl_seconds,
        }
        _save_state(state)

    return {
        "container_id": container_id,
        "container_name": name,
        "host_ip": host_ip,
        "host_ports": host_ports,
    }


def handle_container_teardown(params: dict) -> dict:
    cid = params["container_id"]
    # TODO: subprocess.call(["docker", "rm", "-f", cid])
    with _state_lock:
        state = _load_state()
        state["containers"].pop(cid, None)
        _save_state(state)
    return {"container_id": cid, "removed": True}


def handle_container_list(_params: dict) -> list[dict]:
    # TODO: cross-check with `docker ps` and reconcile.
    state = _load_state()
    return list(state["containers"].values())


def handle_container_inspect(params: dict) -> dict:
    state = _load_state()
    row = state["containers"].get(params["container_id"])
    if not row:
        raise KeyError("unknown container")
    return row


# ---------- Dispatch ----------

METHODS = {
    "ping":                lambda p: {"pong": int(time.time())},
    "wg.generate_peer":    handle_wg_generate_peer,
    "wg.revoke_peer":      handle_wg_revoke_peer,
    "wg.render_config":    handle_wg_render_config,
    "container.spawn":     handle_container_spawn,
    "container.teardown":  handle_container_teardown,
    "container.list":      handle_container_list,
    "container.inspect":   handle_container_inspect,
}


# ---------- Wire protocol ----------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf.extend(chunk)
    return bytes(buf)


def _send_framed(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _serve_one(conn: socket.socket) -> None:
    try:
        header = _recv_exact(conn, 4)
        (length,) = struct.unpack(">I", header)
        if length > 1024 * 1024:
            _reply(conn, ok=False, error="payload too large")
            return
        payload = _recv_exact(conn, length)
        sig = _recv_exact(conn, 64).decode()

        expected = hmac_new(HMAC_KEY, payload, sha256).hexdigest()
        if not compare_digest(sig, expected):
            log.warning("HMAC mismatch — rejecting")
            _reply(conn, ok=False, error="unauthorized")
            return

        req = json.loads(payload)
        ts = int(req.get("ts") or 0)
        if abs(time.time() - ts) > MAX_REPLAY_WINDOW:
            _reply(conn, ok=False, error="stale request")
            return

        method = req.get("method", "")
        handler = METHODS.get(method)
        if not handler:
            _reply(conn, ok=False, error=f"unknown method: {method}")
            return

        try:
            result = handler(req.get("params") or {})
            _reply(conn, ok=True, result=result)
        except Exception as e:
            log.exception("handler %s failed", method)
            _reply(conn, ok=False, error=str(e))

    except (ConnectionError, struct.error) as e:
        log.warning("bad connection: %s", e)


def _reply(conn: socket.socket, **kwargs) -> None:
    _send_framed(conn, json.dumps(kwargs, separators=(",", ":")).encode())


def _chown_socket(path: str) -> None:
    """Apply owner + mode from EDO_SOCKET_OWNER (user:group)."""
    try:
        user, group = SOCKET_OWNER.split(":", 1)
    except ValueError:
        log.warning("EDO_SOCKET_OWNER malformed, leaving default perms")
        return
    import pwd, grp
    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid
    os.chown(path, uid, gid)
    os.chmod(path, SOCKET_MODE)


def main() -> None:
    if not HMAC_KEY:
        log.error("EDO_DAEMON_HMAC_KEY is empty — refusing to start")
        sys.exit(1)

    Path(SOCKET_PATH).parent.mkdir(parents=True, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCKET_PATH)
    _chown_socket(SOCKET_PATH)
    srv.listen(32)
    log.info("edo-daemon listening on %s", SOCKET_PATH)

    stopping = threading.Event()
    def _stop(_sig, _frm):
        log.info("shutdown signal")
        stopping.set()
        try: srv.close()
        except OSError: pass
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while not stopping.is_set():
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        # Thread-per-connection is fine at CTF scale (dozens of requests/sec).
        threading.Thread(target=_serve_one, args=(conn,), daemon=True).start()

    try: os.unlink(SOCKET_PATH)
    except OSError: pass
    log.info("stopped")


if __name__ == "__main__":
    main()
