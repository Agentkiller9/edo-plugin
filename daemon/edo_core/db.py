"""SQLite state manager for the edo daemon.

Adapted from edo's src/db_mgr.py — same transaction discipline (manual
BEGIN/COMMIT/ROLLBACK, WAL, a single re-entrant lock so concurrent RPC
handlers can't trample each other), same atomic allocate-with-retry pattern
for anything that hands out a unique resource (IP, octet).

Three tables, none of which exist in edo's real schema:
  * peers        — WireGuard clients. Same shape as edo's Peer, PLUS
                    owner_type/owner_id so the firewall rule builder can
                    group peers by which owner (team or user) they belong to.
  * owner_octets — one octet (1-254) per owner, used to derive that owner's
                    private /24 inside 10.9.0.0/16. This table has no
                    equivalent in edo — edo has a single flat docker subnet.
  * instances    — running per-owner containers. Analogous to edo's
                    Container, but keyed by (owner_type, owner_id,
                    challenge_ref) instead of challenge_name alone, and
                    carries expires_at for TTL tracking edo doesn't have.

This is the daemon's OWN state — authoritative for what's actually running.
The CTFd plugin's SQL database records *intent*; this file records *actual*.
The reconciler (edo_daemon.py) is what reconciles the two.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path("/var/lib/edo/edo-daemon.db")

SCHEMA_VERSION = 1


@dataclass
class Peer:
    id: int
    owner_type: str
    owner_id: int
    username: str
    ip_address: str
    public_key: str
    private_key: Optional[str]


@dataclass
class OwnerOctet:
    owner_type: str
    owner_id: int
    octet: int


@dataclass
class Instance:
    id: int
    container_id: str
    container_name: str
    owner_type: str
    owner_id: int
    challenge_ref: str
    assigned_ip: str
    ports: str  # JSON-encoded
    status: str
    expires_at: Optional[str]  # ISO 8601 text; NULL means no TTL


class DatabaseManager:
    """Thread-safe SQLite wrapper. One instance per daemon process."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(str(self.db_path), isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("BEGIN")
            try:
                yield conn
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS peers (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_type  TEXT NOT NULL,
                    owner_id    INTEGER NOT NULL,
                    username    TEXT UNIQUE NOT NULL,
                    ip_address  TEXT UNIQUE NOT NULL,
                    public_key  TEXT NOT NULL,
                    private_key TEXT,
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            c.execute(
                "CREATE INDEX IF NOT EXISTS idx_peers_owner ON peers(owner_type, owner_id)"
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS owner_octets (
                    owner_type TEXT NOT NULL,
                    owner_id   INTEGER NOT NULL,
                    octet      INTEGER UNIQUE NOT NULL CHECK (octet BETWEEN 1 AND 254),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (owner_type, owner_id)
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS instances (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    container_id   TEXT UNIQUE NOT NULL,
                    container_name TEXT NOT NULL,
                    owner_type     TEXT NOT NULL,
                    owner_id       INTEGER NOT NULL,
                    challenge_ref  TEXT NOT NULL,
                    assigned_ip    TEXT NOT NULL,
                    ports          TEXT,
                    status         TEXT NOT NULL DEFAULT 'running',
                    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at     TIMESTAMP,
                    UNIQUE (owner_type, owner_id, challenge_ref)
                )
                """
            )
            c.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ---- peers -------------------------------------------------------

    def allocate_peer(
        self,
        owner_type: str,
        owner_id: int,
        username: str,
        public_key: str,
        candidate_ips: List[str],
        private_key: Optional[str] = None,
    ) -> Peer:
        """Pick the first free IP and insert the peer in one transaction.

        Same race-tolerant retry as edo's allocate_peer: recompute the free
        set and retry on an ip_address collision; a username collision is
        not a race and raises immediately.
        """
        attempts = max(8, len(candidate_ips))
        last_error: Optional[Exception] = None
        for _ in range(attempts):
            try:
                with self._conn() as c:
                    used = {
                        r["ip_address"] for r in c.execute("SELECT ip_address FROM peers")
                    }
                    ip = next((x for x in candidate_ips if x not in used), None)
                    if ip is None:
                        raise RuntimeError("WireGuard subnet is exhausted")
                    cur = c.execute(
                        "INSERT INTO peers"
                        " (owner_type, owner_id, username, ip_address, public_key, private_key)"
                        " VALUES (?, ?, ?, ?, ?, ?)",
                        (owner_type, owner_id, username, ip, public_key, private_key),
                    )
                    return Peer(
                        id=int(cur.lastrowid),
                        owner_type=owner_type,
                        owner_id=owner_id,
                        username=username,
                        ip_address=ip,
                        public_key=public_key,
                        private_key=private_key,
                    )
            except sqlite3.IntegrityError as e:
                msg = str(e).lower()
                if "username" in msg:
                    raise ValueError(f"peer '{username}' already exists") from e
                if "ip_address" in msg:
                    last_error = e
                    continue
                raise
        raise RuntimeError(
            f"could not allocate an IP for '{username}' after {attempts} attempts"
            f" (last error: {last_error})"
        )

    def remove_peer(self, username: str) -> bool:
        with self._conn() as c:
            cur = c.execute("DELETE FROM peers WHERE username = ?", (username,))
            return cur.rowcount > 0

    def get_peer(self, username: str) -> Optional[Peer]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM peers WHERE username = ?", (username,)).fetchone()
        return _row_to_peer(row) if row else None

    def get_peer_by_owner(self, owner_type: str, owner_id: int) -> List[Peer]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM peers WHERE owner_type = ? AND owner_id = ? ORDER BY id",
                (owner_type, owner_id),
            ).fetchall()
        return [_row_to_peer(r) for r in rows]

    def get_all_peers(self) -> List[Peer]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM peers ORDER BY id").fetchall()
        return [_row_to_peer(r) for r in rows]

    def get_used_peer_ips(self) -> List[str]:
        with self._conn() as c:
            rows = c.execute("SELECT ip_address FROM peers").fetchall()
        return [r["ip_address"] for r in rows]

    def peers_grouped_by_owner(self) -> dict:
        """Return {(owner_type, owner_id): [ip_address, ...]} for every peer.

        Used by the firewall rule builder — it needs to know, per owner,
        which WireGuard addresses are allowed to reach that owner's
        container subnet.
        """
        out: dict = {}
        for p in self.get_all_peers():
            out.setdefault((p.owner_type, p.owner_id), []).append(p.ip_address)
        return out

    # ---- owner octets --------------------------------------------------

    def allocate_octet(self, owner_type: str, owner_id: int) -> int:
        """Idempotently return this owner's octet, allocating one if needed.

        Same atomic-retry shape as allocate_peer. Octets are 1-254 (0 and
        255 reserved). Returns the existing octet if this owner already has
        one — spawning a second instance for the same owner must land on
        the same subnet as the first.
        """
        existing = self.get_octet(owner_type, owner_id)
        if existing is not None:
            return existing

        attempts = 254
        last_error: Optional[Exception] = None
        for _ in range(attempts):
            try:
                with self._conn() as c:
                    used = {
                        r["octet"] for r in c.execute("SELECT octet FROM owner_octets")
                    }
                    octet = next((o for o in range(1, 255) if o not in used), None)
                    if octet is None:
                        raise RuntimeError(
                            "docker subnet pool exhausted (254 owners already allocated)"
                        )
                    c.execute(
                        "INSERT INTO owner_octets (owner_type, owner_id, octet)"
                        " VALUES (?, ?, ?)",
                        (owner_type, owner_id, octet),
                    )
                    return octet
            except sqlite3.IntegrityError as e:
                last_error = e
                continue
        raise RuntimeError(f"could not allocate an octet (last error: {last_error})")

    def get_octet(self, owner_type: str, owner_id: int) -> Optional[int]:
        with self._conn() as c:
            row = c.execute(
                "SELECT octet FROM owner_octets WHERE owner_type = ? AND owner_id = ?",
                (owner_type, owner_id),
            ).fetchone()
        return int(row["octet"]) if row else None

    def free_octet(self, owner_type: str, owner_id: int) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM owner_octets WHERE owner_type = ? AND owner_id = ?",
                (owner_type, owner_id),
            )
            return cur.rowcount > 0

    def get_all_owner_octets(self) -> List[OwnerOctet]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM owner_octets ORDER BY octet").fetchall()
        return [
            OwnerOctet(owner_type=r["owner_type"], owner_id=r["owner_id"], octet=r["octet"])
            for r in rows
        ]

    # ---- instances -------------------------------------------------------

    def add_instance(
        self,
        container_id: str,
        container_name: str,
        owner_type: str,
        owner_id: int,
        challenge_ref: str,
        assigned_ip: str,
        ports: str,
        expires_at: Optional[str],
        status: str = "running",
    ) -> Instance:
        try:
            with self._conn() as c:
                cur = c.execute(
                    "INSERT INTO instances"
                    " (container_id, container_name, owner_type, owner_id,"
                    "  challenge_ref, assigned_ip, ports, status, expires_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        container_id, container_name, owner_type, owner_id,
                        challenge_ref, assigned_ip, ports, status, expires_at,
                    ),
                )
                row_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as e:
            raise ValueError(f"instance record collision: {e}") from e
        return Instance(
            id=row_id, container_id=container_id, container_name=container_name,
            owner_type=owner_type, owner_id=owner_id, challenge_ref=challenge_ref,
            assigned_ip=assigned_ip, ports=ports, status=status, expires_at=expires_at,
        )

    def remove_instance(self, container_id: str) -> bool:
        with self._conn() as c:
            cur = c.execute("DELETE FROM instances WHERE container_id = ?", (container_id,))
            return cur.rowcount > 0

    def find_instance(
        self, owner_type: str, owner_id: int, challenge_ref: str
    ) -> Optional[Instance]:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM instances"
                " WHERE owner_type = ? AND owner_id = ? AND challenge_ref = ?",
                (owner_type, owner_id, challenge_ref),
            ).fetchone()
        return _row_to_instance(row) if row else None

    def get_active_instances(self) -> List[Instance]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM instances WHERE status = 'running' ORDER BY id"
            ).fetchall()
        return [_row_to_instance(r) for r in rows]

    def get_all_instances(self) -> List[Instance]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM instances ORDER BY id").fetchall()
        return [_row_to_instance(r) for r in rows]

    def get_used_instance_ips(self, owner_type: str, owner_id: int) -> List[str]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT assigned_ip FROM instances"
                " WHERE owner_type = ? AND owner_id = ? AND status = 'running'",
                (owner_type, owner_id),
            ).fetchall()
        return [r["assigned_ip"] for r in rows]

    def count_instances_for_owner(self, owner_type: str, owner_id: int) -> int:
        with self._conn() as c:
            row = c.execute(
                "SELECT COUNT(*) AS n FROM instances WHERE owner_type = ? AND owner_id = ?",
                (owner_type, owner_id),
            ).fetchone()
        return int(row["n"])

    def update_instance_status(self, container_id: str, status: str) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE instances SET status = ? WHERE container_id = ?",
                (status, container_id),
            )
            return cur.rowcount > 0


def _row_to_peer(row: sqlite3.Row) -> Peer:
    return Peer(
        id=row["id"], owner_type=row["owner_type"], owner_id=row["owner_id"],
        username=row["username"], ip_address=row["ip_address"],
        public_key=row["public_key"], private_key=row["private_key"],
    )


def _row_to_instance(row: sqlite3.Row) -> Instance:
    return Instance(
        id=row["id"], container_id=row["container_id"], container_name=row["container_name"],
        owner_type=row["owner_type"], owner_id=row["owner_id"],
        challenge_ref=row["challenge_ref"], assigned_ip=row["assigned_ip"],
        ports=row["ports"], status=row["status"], expires_at=row["expires_at"],
    )
