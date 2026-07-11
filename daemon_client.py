"""
EdoDaemonClient: JSON-over-Unix-socket RPC to the root edo-daemon.

Wire format (one call per connection to avoid framing headaches under load):
    request  = 4-byte big-endian length | JSON payload
    response = 4-byte big-endian length | JSON payload

Every request carries an HMAC-SHA256 signature over the JSON payload using a
shared secret from EDO_DAEMON_HMAC_KEY. This isn't a substitute for socket
permissions — it's belt-and-braces so a compromised non-root process on the
box can't forge RPCs even if the socket ends up world-writable by accident.

Kept intentionally dependency-free (stdlib only) so it can run inside the
CTFd worker without pulling gRPC/HTTP client libs.
"""
from __future__ import annotations

import hmac
import json
import logging
import socket
import struct
import time
from hashlib import sha256
from typing import Any

logger = logging.getLogger("edo.daemon_client")


class DaemonError(Exception):
    """Anything the daemon reports as an error, or an RPC that never landed."""


class DaemonTimeout(DaemonError):
    """Socket read/write timed out."""


class DaemonUnavailable(DaemonError):
    """The socket is missing or refused connection — daemon likely down."""


class EdoDaemonClient:
    """Thin RPC client. Instances are cheap; create per-request or reuse."""

    def __init__(self, socket_path: str, hmac_key: bytes, timeout: int = 30):
        self.socket_path = socket_path
        self._hmac_key = hmac_key
        self.timeout = timeout

    # ---------- low-level ----------

    def _call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        payload = json.dumps(
            {"method": method, "params": params or {}, "ts": int(time.time())},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

        if not self._hmac_key:
            # Fail closed: an unsigned RPC is a config bug we shouldn't paper over.
            raise DaemonError("EDO_DAEMON_HMAC_KEY not configured")

        sig = hmac.new(self._hmac_key, payload, sha256).hexdigest()
        framed = struct.pack(">I", len(payload)) + payload + sig.encode()

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

    def wg_generate_peer(self, user_id: int, team_id: int | None) -> dict:
        """
        Ask the daemon to allocate a peer inside the VPN subnet.

        Returns: {public_key, private_key, assigned_ip, server_public_key,
                  endpoint, allowed_ips, dns}
        """
        return self._call("wg.generate_peer", {"user_id": user_id, "team_id": team_id})

    def wg_revoke_peer(self, public_key: str) -> dict:
        return self._call("wg.revoke_peer", {"public_key": public_key})

    def wg_render_config(self, peer: dict) -> str:
        """Ask the daemon for a ready-to-import .conf blob for a peer."""
        return self._call("wg.render_config", {"peer": peer})

    # ---------- Containers ----------

    def container_spawn(
        self,
        challenge_id: int,
        team_id: int | None,
        user_id: int | None,
        image: str,
        exposed_ports: list[str],
        cpu_limit: float,
        memory_mb: int,
        pids_limit: int,
        ttl_seconds: int,
    ) -> dict:
        """
        Spawn one isolated container for (challenge, team).

        Returns: {container_id, container_name, host_ip, host_ports}
        """
        return self._call(
            "container.spawn",
            {
                "challenge_id": challenge_id,
                "team_id": team_id,
                "user_id": user_id,
                "image": image,
                "exposed_ports": exposed_ports,
                "cpu_limit": cpu_limit,
                "memory_mb": memory_mb,
                "pids_limit": pids_limit,
                "ttl_seconds": ttl_seconds,
            },
        )

    def container_teardown(self, container_id: str) -> dict:
        return self._call("container.teardown", {"container_id": container_id})

    def container_list(self) -> list[dict]:
        """
        Return every container the daemon believes is alive.

        Used by the reconciler; do not call from user-facing paths.
        Each row: {container_id, container_name, challenge_id, team_id,
                   user_id, status, host_ip, host_ports}
        """
        return self._call("container.list", {})

    def container_inspect(self, container_id: str) -> dict:
        return self._call("container.inspect", {"container_id": container_id})

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
