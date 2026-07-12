#!/usr/bin/env python3
"""
edo-daemon: root-privileged sidecar for the CTFd edo-plugin.

v2: authenticates callers via SO_PEERCRED (the kernel-verified UID of the
connecting process) instead of an HMAC secret. The socket's filesystem
permissions (0660 root:<group>) control who can even attempt to connect;
SO_PEERCRED then confirms the connecting process really is running as the
configured CTFd UID — a check an attacker can't forge by stealing an
application-layer token, because it's enforced by the kernel on the socket
itself, not by anything either side sends.

All the actual infrastructure logic (WireGuard, per-owner Docker networks,
iptables isolation, container lifecycle) lives in edo_core/ — this file is
just the RPC server and dispatch table.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import socket
import struct
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from edo_core import containers, wireguard
from edo_core.db import DatabaseManager
from edo_core.network import apply_firewall, remove_firewall

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("edo-daemon")

# ---------- Config (env-driven) ----------
SOCKET_PATH = os.environ.get("EDO_SOCKET_PATH", "/run/edo/edo.sock")
STATE_DB = Path(os.environ.get("EDO_STATE_DB", "/var/lib/edo/edo-daemon.db"))
SOCKET_OWNER = os.environ.get("EDO_SOCKET_OWNER", "root:ctfd")
SOCKET_MODE = 0o660

# The UID the CTFd process runs as. This is the actual auth boundary — a
# connection from any other non-root UID is rejected outright.
ALLOWED_UID = os.environ.get("EDO_ALLOWED_UID")

VPN_ENDPOINT = os.environ.get("EDO_VPN_ENDPOINT", "vpn.example.com:51820")
VPN_PORT = int(os.environ.get("EDO_VPN_PORT", "51820"))

# Cap on concurrent `docker build` / container-create operations so a burst
# of simultaneous "spawn" clicks doesn't fork off dozens of builds at once.
_SPAWN_SEMAPHORE = threading.Semaphore(int(os.environ.get("EDO_MAX_CONCURRENT_SPAWNS", "4")))

db: DatabaseManager  # set in main()


# ---------- SO_PEERCRED auth ----------
def _peer_credentials(conn: socket.socket) -> tuple[int, int, int]:
    so_peercred = getattr(socket, "SO_PEERCRED", 17)  # 17 is the Linux constant
    creds = conn.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", creds)
    return pid, uid, gid


def _authorized(uid: int) -> bool:
    if uid == 0:
        return True  # root (e.g. an operator debugging via socat) is always trusted
    return ALLOWED_UID is not None and uid == int(ALLOWED_UID)


# ---------- Firewall rebuild helper ----------
def _rebuild_firewall() -> None:
    peers_by_owner = db.peers_grouped_by_owner()
    octets_by_owner = {
        (o.owner_type, o.owner_id): o.octet for o in db.get_all_owner_octets()
    }
    try:
        apply_firewall(peers_by_owner, octets_by_owner, wg_port=VPN_PORT)
    except RuntimeError:
        log.exception("firewall rebuild failed")
        raise


# ---------- Command handlers ----------
def handle_ping(_params: dict) -> dict:
    return {"pong": True}


def handle_wg_ensure_peer(params: dict) -> dict:
    user_id = int(params["user_id"])
    owner_type = params["owner_type"]
    owner_id = int(params["owner_id"])
    username = f"user_{user_id}"

    existing = db.get_peer(username)
    if existing is None:
        server = wireguard.load_server_config(VPN_ENDPOINT, VPN_PORT)
        client_cfg = wireguard.add_peer(
            db, owner_type=owner_type, owner_id=owner_id, username=username, server=server,
        )
        _rebuild_firewall()
        peer = client_cfg.peer
    else:
        peer = existing
        server = wireguard.load_server_config(VPN_ENDPOINT, VPN_PORT)

    return {
        "username": peer.username,
        "public_key": peer.public_key,
        "private_key": peer.private_key,
        "assigned_ip": peer.ip_address,
        "server_public_key": server.public_key,
        "endpoint": server.endpoint,
        "listen_port": server.listen_port,
    }


def handle_wg_remove_peer(params: dict) -> dict:
    user_id = int(params["user_id"])
    username = f"user_{user_id}"
    removed = wireguard.remove_peer(db, username)
    if removed:
        _rebuild_firewall()
    return {"removed": removed}


def handle_wg_render_config(params: dict) -> str:
    user_id = int(params["user_id"])
    username = f"user_{user_id}"
    peer = db.get_peer(username)
    if peer is None:
        raise KeyError(f"no peer for user {user_id}")
    server = wireguard.load_server_config(VPN_ENDPOINT, VPN_PORT)
    return wireguard.render_client_config(peer, server)


def handle_container_ensure_instance(params: dict) -> dict:
    sec = params.get("security") or {}
    from edo_core.containers import SecurityProfile

    profile = SecurityProfile(
        no_new_privileges=sec.get("no_new_privileges", True),
        cap_drop=sec.get("cap_drop", ["NET_RAW"]),
        cap_add=sec.get("cap_add", []),
        read_only_rootfs=sec.get("read_only_rootfs", False),
        memory=sec.get("memory"),
        cpus=sec.get("cpus"),
        pids_limit=sec.get("pids_limit"),
        restart_policy=sec.get("restart_policy", "unless-stopped"),
    )
    with _SPAWN_SEMAPHORE:
        result = containers.spawn_instance(
            db,
            owner_type=params["owner_type"],
            owner_id=int(params["owner_id"]),
            challenge_ref=str(params["challenge_ref"]),
            build_path=Path(params["build_path"]),
            security=profile,
            ttl_seconds=params.get("ttl_seconds"),
        )
    if not result.success:
        raise RuntimeError(result.error or "spawn failed")
    _rebuild_firewall()
    inst = result.instance
    return {
        "container_id": inst.container_id,
        "container_name": inst.container_name,
        "assigned_ip": inst.assigned_ip,
        "ports": json.loads(inst.ports) if inst.ports else [],
        "expires_at": inst.expires_at,
        "status": inst.status,
    }


def handle_container_release_instance(params: dict) -> dict:
    container_id = params["container_id"]
    removed = containers.release_instance(db, container_id)
    _rebuild_firewall()
    return {"removed": removed}


def handle_container_reconcile(_params: dict) -> dict:
    pruned = containers.reconcile(db)
    instances = [
        {
            "container_id": i.container_id, "container_name": i.container_name,
            "owner_type": i.owner_type, "owner_id": i.owner_id,
            "challenge_ref": i.challenge_ref, "assigned_ip": i.assigned_ip,
            "ports": json.loads(i.ports) if i.ports else [],
            "status": i.status, "expires_at": i.expires_at,
        }
        for i in db.get_all_instances()
    ]
    return {"pruned": pruned, "instances": instances}


def handle_container_inspect(params: dict) -> dict:
    container_id = params["container_id"]
    for i in db.get_all_instances():
        if i.container_id == container_id:
            return {
                "container_id": i.container_id, "container_name": i.container_name,
                "owner_type": i.owner_type, "owner_id": i.owner_id,
                "challenge_ref": i.challenge_ref, "assigned_ip": i.assigned_ip,
                "ports": json.loads(i.ports) if i.ports else [],
                "status": i.status, "expires_at": i.expires_at,
            }
    raise KeyError(f"unknown container {container_id}")


def handle_kill_switch(_params: dict) -> dict:
    """Emergency stop: tears down every tracked container. Deliberately
    leaves WireGuard peers intact — this is a container kill switch, not a
    VPN lockout; use wg.remove_peer per-peer if you also need to cut
    network access.
    """
    count = containers.teardown_all(db)
    _rebuild_firewall()
    return {"containers_removed": count}


METHODS: dict[str, Callable[[dict], Any]] = {
    "ping": handle_ping,
    "wg.ensure_peer": handle_wg_ensure_peer,
    "wg.remove_peer": handle_wg_remove_peer,
    "wg.render_config": handle_wg_render_config,
    "container.ensure_instance": handle_container_ensure_instance,
    "container.release_instance": handle_container_release_instance,
    "container.reconcile": handle_container_reconcile,
    "container.inspect": handle_container_inspect,
    "kill_switch": handle_kill_switch,
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


def _reply(conn: socket.socket, **kwargs) -> None:
    _send_framed(conn, json.dumps(kwargs, separators=(",", ":")).encode())


def _serve_one(conn: socket.socket) -> None:
    try:
        pid, uid, gid = _peer_credentials(conn)
        if not _authorized(uid):
            log.warning("rejected connection from uid=%d pid=%d", uid, pid)
            _reply(conn, ok=False, error="unauthorized")
            return

        header = _recv_exact(conn, 4)
        (length,) = struct.unpack(">I", header)
        if length > 4 * 1024 * 1024:
            _reply(conn, ok=False, error="payload too large")
            return
        payload = _recv_exact(conn, length)
        req = json.loads(payload)

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
    except (ConnectionError, struct.error, json.JSONDecodeError) as e:
        log.warning("bad connection: %s", e)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _chown_socket(path: str) -> None:
    try:
        user, group = SOCKET_OWNER.split(":", 1)
    except ValueError:
        log.warning("EDO_SOCKET_OWNER malformed, leaving default perms")
        return
    import grp
    import pwd

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid
    os.chown(path, uid, gid)
    os.chmod(path, SOCKET_MODE)


def main() -> None:
    global db

    if not ALLOWED_UID:
        log.error("EDO_ALLOWED_UID is not set — refusing to start (would authenticate no one)")
        sys.exit(1)

    STATE_DB.parent.mkdir(parents=True, exist_ok=True)
    db = DatabaseManager(STATE_DB)

    # Bring up WireGuard and reconcile Docker/firewall state before we start
    # accepting RPCs, so the first request never races a half-initialized
    # daemon.
    try:
        wireguard.init_server(VPN_ENDPOINT, VPN_PORT)
        wireguard.bring_up()
    except RuntimeError:
        log.exception("WireGuard init failed — VPN features will error until fixed")

    try:
        adopted = containers.adopt_untracked(db)
        pruned = containers.reconcile(db)
        log.info("startup reconcile: adopted=%d pruned=%d", adopted, pruned)
    except RuntimeError:
        log.exception("container reconcile failed — is Docker running?")

    try:
        _rebuild_firewall()
    except RuntimeError:
        log.exception("initial firewall apply failed")

    Path(SOCKET_PATH).parent.mkdir(parents=True, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCKET_PATH)
    _chown_socket(SOCKET_PATH)
    srv.listen(32)
    log.info("edo-daemon listening on %s (allowed uid=%s)", SOCKET_PATH, ALLOWED_UID)

    stopping = threading.Event()

    def _stop(_sig, _frm):
        log.info("shutdown signal")
        stopping.set()
        try:
            srv.close()
        except OSError:
            pass

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while not stopping.is_set():
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=_serve_one, args=(conn,), daemon=True).start()

    try:
        os.unlink(SOCKET_PATH)
    except OSError:
        pass
    log.info("stopped")


if __name__ == "__main__":
    main()
