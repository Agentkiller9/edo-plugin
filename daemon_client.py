"""
EdoDaemonClient: JSON-over-Unix-socket RPC to the root edo-daemon.

Wire format (one call per connection to avoid framing headaches under load):
    request  = 4-byte big-endian length | JSON payload
    response = 4-byte big-endian length | JSON payload

There is no application-layer signing here. Authentication is enforced by
the daemon reading this process's real UID off the socket via SO_PEERCRED —
a kernel-level check the daemon performs on every accepted connection,
which is why the socket's filesystem permissions (0660, owned by
root:<ctfd-group>) matter: they're what lets this process connect at all,
and SO_PEERCRED is what confirms it really is who the permissions say it is.
Nothing this client sends could forge that.

Kept intentionally dependency-free (stdlib only) so it can run inside the
CTFd worker without pulling extra client libs.
"""
from __future__ import annotations

import json
import logging
import socket
import struct
import time
from typing import Any, Optional

logger = logging.getLogger("edo.daemon_client")


class DaemonError(Exception):
    """Anything the daemon reports as an error, or an RPC that never landed."""


class DaemonTimeout(DaemonError):
    """Socket read/write timed out."""


class DaemonUnavailable(DaemonError):
    """The socket is missing or refused connection — daemon likely down."""


class EdoDaemonClient:
    """Thin RPC client. Instances are cheap; create per-request or reuse."""

    def __init__(self, socket_path: str, timeout: int = 30):
        self.socket_path = socket_path
        self.timeout = timeout

    # ---------- low-level ----------

    def _call(self, method: str, params: Optional[dict] = None) -> Any:
        payload = json.dumps(
            {"method": method, "params": params or {}, "ts": int(time.time())},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        framed = struct.pack(">I", len(payload)) + payload

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.socket_path)
                s.sendall(framed)
                resp = _recv_framed(s)
        except FileNotFoundError as e:
            raise DaemonUnavailable(f"socket missing: {self.socket_path}") from e
        except ConnectionRefusedError as e:
            raise DaemonUnavailable("daemon refused connection") from e
        except socket.timeout as e:
            raise DaemonTimeout(f"RPC {method} timed out after {self.timeout}s") from e
        except OSError as e:
            raise DaemonError(f"socket error: {e}") from e

        try:
            data = json.loads(resp)
        except json.JSONDecodeError as e:
            raise DaemonError(f"malformed response: {e}") from e

        if not data.get("ok"):
            raise DaemonError(data.get("error", "unknown daemon error"))
        return data.get("result")

    # ---------- WireGuard ----------

    def wg_ensure_peer(self, user_id: int, owner_type: str, owner_id: int) -> dict:
        """
        Idempotently get-or-create a WireGuard peer for this CTFd user.

        Returns: {username, public_key, private_key, assigned_ip,
                  server_public_key, endpoint, listen_port}
        """
        return self._call(
            "wg.ensure_peer",
            {"user_id": user_id, "owner_type": owner_type, "owner_id": owner_id},
        )

    def wg_remove_peer(self, user_id: int) -> dict:
        return self._call("wg.remove_peer", {"user_id": user_id})

    def wg_render_config(self, user_id: int) -> str:
        """Ask the daemon for a ready-to-import .conf blob for this user."""
        return self._call("wg.render_config", {"user_id": user_id})

    # ---------- Containers ----------

    def container_ensure_instance(
        self,
        owner_type: str,
        owner_id: int,
        challenge_ref: str,
        build_path: str,
        exposed_ports: Optional[list] = None,
        security: Optional[dict] = None,
        ttl_seconds: Optional[int] = None,
    ) -> dict:
        """
        Idempotently spawn (or return the existing) container for
        (owner_type, owner_id, challenge_ref).

        Returns: {container_id, container_name, assigned_ip, ports,
                  expires_at, status}
        """
        return self._call(
            "container.ensure_instance",
            {
                "owner_type": owner_type,
                "owner_id": owner_id,
                "challenge_ref": challenge_ref,
                "build_path": build_path,
                "ports": exposed_ports or [],
                "security": security or {},
                "ttl_seconds": ttl_seconds,
            },
        )

    def container_release_instance(self, container_id: str) -> dict:
        return self._call("container.release_instance", {"container_id": container_id})

    def container_reconcile(self) -> dict:
        """
        Ask the daemon to reconcile its DB against real Docker state and
        return everything it's currently tracking.

        Returns: {pruned: int, instances: [{container_id, container_name,
                  owner_type, owner_id, challenge_ref, assigned_ip, ports,
                  status, expires_at}, ...]}
        """
        return self._call("container.reconcile", {})

    def container_inspect(self, container_id: str) -> dict:
        return self._call("container.inspect", {"container_id": container_id})

    # ---------- Emergency ----------

    def kill_switch(self) -> dict:
        """Tear down every tracked container. Leaves VPN peers intact."""
        return self._call("kill_switch", {})

    # ---------- Health ----------

    def ping(self) -> dict:
        return self._call("ping", {})


def _recv_framed(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length > 16 * 1024 * 1024:
        raise DaemonError(f"response too large: {length} bytes")
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise DaemonError("short read from daemon")
        buf.extend(chunk)
    return bytes(buf)
