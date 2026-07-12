"""
SQLAlchemy models for edo-plugin.

v2 design notes (see README for the full rationale):

- **Owner model.** CTFd runs in either "users" or "teams" mode. Rather than
  carrying separate nullable user_id/team_id columns everywhere, every
  owner-scoped table here uses a generic (owner_type, owner_id) pair —
  owner_type is "user" or "team", owner_id is that row's id in CTFd's own
  Users/Teams table. There's deliberately no FK on owner_id (it's
  polymorphic — it can't point at two different tables at once); resolution
  happens through owner.py's resolve_owner(), which wraps CTFd's own
  get_model()/get_current_user()/get_current_team().

- **Flags are CTFd's native Flags table, not a reimplementation.** CTFd
  already supports multiple Flags rows per challenge and loops over them in
  attempt() via get_flag_class(flag.type).compare(). Reimplementing that
  (the v1 EdoFlag model) would have thrown away CTFd's flag-type plugins,
  the built-in flag editor, and import/export — for nothing. EdoFlagWeight
  is the ONLY new table on the flags side: one row per native Flag,
  attaching the percentage of challenge value it's worth.

- **EdoInstance tracks live containers**, one per (challenge, owner) — a
  soft mirror of the daemon's own SQLite state. The daemon is authoritative
  for what's actually running; the reconciler is what keeps this table
  honest (see scheduler.py).

- **No EdoOwnerOctet here.** Per-owner subnet allocation is infrastructure
  *actual* state, not CTFd *intent* — it lives entirely in the daemon's own
  SQLite (daemon/edo_core/db.py). The plugin never needs to know an
  owner's octet; it only ever talks to the daemon in terms of
  (owner_type, owner_id).

- **EdoSettings** is a tiny key/value store so admins can tune the plugin
  without editing config.py.
"""
from datetime import datetime

from CTFd.models import Challenges, db


class EdoChallenge(Challenges):
    """A CTFd challenge with multi-flag support, difficulty, and container spawning."""

    __mapper_args__ = {"polymorphic_identity": "edo"}
    id = db.Column(
        db.Integer,
        db.ForeignKey("challenges.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # --- Difficulty (Easy / Medium / Hard / Very Hard) ---
    difficulty = db.Column(db.String(16), default="medium", nullable=False)

    # --- Scoring model: "static" or "dynamic" (decay). ---
    scoring_mode = db.Column(db.String(16), default="static", nullable=False)
    # Dynamic-scoring params — ignored when scoring_mode == "static".
    initial_value = db.Column(db.Integer, default=500)
    minimum_value = db.Column(db.Integer, default=100)
    decay = db.Column(db.Integer, default=25)  # solves before minimum reached

    # --- Container / instance config ---
    # Host filesystem path to a directory containing a Dockerfile. The
    # daemon builds from this path (edo_core.containers.build_image) rather
    # than pulling a pre-built image — matches how edo's own docker_mgr
    # works, and means admins don't need a separate registry push step.
    build_path = db.Column(db.String(512))
    # No exposed_ports column — the daemon reads the built image's own
    # EXPOSE metadata after each build and reports it back per instance
    # (see EdoInstance.host_ports). No host port is ever published (see
    # daemon/edo_core/containers.py's _build_secure_host_config), so this
    # value was never anything but a display hint duplicating the
    # Dockerfile — removed rather than kept in sync by hand.
    cpu_limit = db.Column(db.Float, default=1.0)     # CPUs (Docker --cpus)
    memory_limit_mb = db.Column(db.Integer, default=512)
    pids_limit = db.Column(db.Integer, default=256)
    read_only_rootfs = db.Column(db.Boolean, default=False, nullable=False)
    # Per-challenge TTL override, in seconds; NULL means "use EdoSettings default".
    ttl_seconds = db.Column(db.Integer)
    # "vpn" (default): participants reach their own container at its routed
    # IP over WireGuard, no host port ever published — the isolation model
    # everything else in this file assumes. "public": the daemon instead
    # publishes each owner's container ports to dynamically-allocated host
    # ports on the server's own public IP, so participants can reach it
    # directly, no VPN required (typical for web-category challenges).
    # Deliberately per-challenge, not global — most challenge types still
    # want the VPN-isolated default; this is an opt-in exception.
    access_mode = db.Column(db.String(8), default="vpn", nullable=False)

    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)


class EdoFlagWeight(db.Model):
    """Percentage weight for one of CTFd's native Flags rows.

    Deliberately NOT a flag reimplementation — content/type/case-sensitivity
    all stay on CTFd's own Flags model and flag-type plugin system. This
    table only adds what CTFd doesn't have: how much of the challenge's
    total value this specific flag is worth.
    """

    __tablename__ = "edo_flag_weights"

    id = db.Column(db.Integer, primary_key=True)
    flag_id = db.Column(
        db.Integer, db.ForeignKey("flags.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    # Percentage 0-100. Sum across a challenge's flags should be 100 —
    # enforced in the admin API, not the DB (admins can save invalid state
    # mid-edit).
    weight_pct = db.Column(db.Integer, default=100, nullable=False)

    flag = db.relationship("Flags", foreign_keys="EdoFlagWeight.flag_id")


class EdoFlagSolve(db.Model):
    """
    Per-owner record of which flags of a multi-flag challenge have been
    solved, keyed generically so this works in both user-mode and team-mode.

    Partial credit: an owner that's found 2 of 3 flags has earned the sum of
    those 2 flags' EdoFlagWeight.weight_pct, out of the challenge's current
    value (see challenge_type.py).
    """

    __tablename__ = "edo_flag_solves"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), nullable=False, index=True
    )
    flag_id = db.Column(
        db.Integer, db.ForeignKey("flags.id", ondelete="CASCADE"), nullable=False, index=True
    )
    owner_type = db.Column(db.String(8), nullable=False)   # "user" | "team"
    owner_id = db.Column(db.Integer, nullable=False)
    solved_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint(
            "owner_type", "owner_id", "flag_id", name="uq_edo_flag_solve_owner"
        ),
    )


class EdoInstance(db.Model):
    """
    One running container for one (challenge, owner) pair.

    Uniqueness constraint enforces "one dedicated container per challenge
    per owner". The daemon is authoritative for `status`; the plugin
    updates the DB after each RPC and the reconciler heals drift.
    """

    __tablename__ = "edo_instances"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), nullable=False, index=True
    )
    owner_type = db.Column(db.String(8), nullable=False)   # "user" | "team"
    owner_id = db.Column(db.Integer, nullable=False, index=True)

    # Daemon-side identifiers. container_id is None until the spawn RPC returns.
    container_id = db.Column(db.String(64), unique=True)
    container_name = db.Column(db.String(128))
    # Where the participant connects: their container's own routed IP on
    # the owner's subnet, over the VPN — never a host-published port (see
    # daemon/edo_core/containers.py). Populated once the daemon reports
    # back. Despite the column name (kept to avoid a migration), this is a
    # JSON LIST of ports the container listens on, e.g. ["1337/tcp"], read
    # from the built image's own EXPOSE metadata — not a host-port mapping.
    assigned_ip = db.Column(db.String(64))
    host_ports = db.Column(db.String(256))
    # Only populated for access_mode="public" challenges: JSON dict mapping
    # container port -> the host port the daemon actually bound it to, e.g.
    # {"80/tcp": 34521}. Ports are dynamically allocated per owner (Docker
    # picks a free ephemeral port), since every owner's container needs its
    # own — there's no fixed port to hardcode. Empty/null for "vpn" mode.
    published_ports = db.Column(db.String(512))

    status = db.Column(db.String(24), default="pending", nullable=False)
    # status ∈ {pending, running, expired, stopped, error, orphaned}

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    last_reconciled_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)

    __table_args__ = (
        db.UniqueConstraint(
            "challenge_id", "owner_type", "owner_id", name="uq_edo_instance_owner_chal"
        ),
    )


class EdoPeer(db.Model):
    """A WireGuard peer for one CTFd user.

    VPN identity is always per-user (never per-team — teammates each keep
    their own device/config), but owner_type/owner_id record which
    container-access scope this peer's traffic is allowed into: the user
    themselves in user-mode, or their team in team-mode. That's the same
    (owner_type, owner_id) the daemon uses to build its per-owner firewall
    ACCEPT rules (see daemon/edo_core/network.py).
    """

    __tablename__ = "edo_peers"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True, unique=True
    )
    owner_type = db.Column(db.String(8), nullable=False)
    owner_id = db.Column(db.Integer, nullable=False, index=True)

    public_key = db.Column(db.String(64), nullable=False)
    # Private key is stored so the user can re-download their .conf. If your
    # threat model forbids this, switch to client-side key generation (the
    # daemon already supports it — see wg.ensure_peer's public_key param).
    private_key = db.Column(db.String(64))
    assigned_ip = db.Column(db.String(64), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    revoked = db.Column(db.Boolean, default=False, nullable=False)


class EdoWorkerLease(db.Model):
    """
    Leader-election row so background jobs (TTL sweep, reconciler) run on
    exactly one gunicorn worker, not once per worker.

    A worker "holds" a lock by winning a conditional UPDATE (only succeeds
    if the lease is unheld, expired, or already held by that same worker)
    or, if the row doesn't exist yet, an INSERT. Both are atomic at the row
    level under any of CTFd's supported databases (MySQL, Postgres, SQLite)
    — no external lock service (Redis, etcd) required.
    """

    __tablename__ = "edo_worker_leases"

    lock_name = db.Column(db.String(64), primary_key=True)
    holder = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class EdoSettings(db.Model):
    """Key/value store for admin-tunable plugin settings."""

    __tablename__ = "edo_settings"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text)

    @classmethod
    def get(cls, key, default=None, cast=str):
        row = cls.query.filter_by(key=key).first()
        if row is None or row.value is None:
            return default
        try:
            return cast(row.value) if cast is not str else row.value
        except (ValueError, TypeError):
            return default

    @classmethod
    def set(cls, key, value):
        row = cls.query.filter_by(key=key).first()
        if row is None:
            row = cls(key=key, value=str(value))
            db.session.add(row)
        else:
            row.value = str(value)
        db.session.commit()


class EdoAuditLog(db.Model):
    """
    Append-only log of infrastructure events.

    Written by the plugin whenever it issues an RPC or the reconciler detects
    drift. Do not truncate — retention is a separate cron concern.
    """

    __tablename__ = "edo_audit_log"

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    actor = db.Column(db.String(64))          # "user:42", "team:7", "reconciler", "scheduler"
    event = db.Column(db.String(64), nullable=False)  # "spawn", "teardown", "extend", "orphan", ...
    challenge_id = db.Column(db.Integer, index=True)
    instance_id = db.Column(db.Integer, index=True)
    details = db.Column(db.Text)              # free-form JSON string
