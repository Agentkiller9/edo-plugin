"""
SQLAlchemy models for edo-plugin.

Design notes:
- EdoChallenge uses joined-table inheritance from CTFd's `Challenges` so it
  slots into the existing challenge machinery (submissions, hints, scoreboard).
- EdoFlag is *separate* from CTFd's built-in Flags table so we can attach a
  weight per flag. We keep CTFd's Flags empty for our challenge type — all
  validation goes through our custom challenge class.
- EdoInstance tracks live containers. It is a soft mirror of daemon state;
  the reconciler is what keeps it honest.
- EdoSettings is a tiny key/value store so admins can tune the plugin without
  editing config.py.
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
    docker_image = db.Column(db.String(256))         # e.g. "registry.local/chall:latest"
    exposed_ports = db.Column(db.String(256))        # CSV: "80/tcp,443/tcp"
    cpu_limit = db.Column(db.Float, default=1.0)     # CPUs (Docker --cpus)
    memory_limit_mb = db.Column(db.Integer, default=512)
    pids_limit = db.Column(db.Integer, default=256)
    # Per-challenge TTL override; NULL means "use EdoSettings default".
    ttl_seconds = db.Column(db.Integer)

    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)


class EdoFlag(db.Model):
    """A flag belonging to an EdoChallenge with a percentage weight of total score."""

    __tablename__ = "edo_flags"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(
        db.Integer,
        db.ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Store hash-friendly type: "static" (case-sensitive) or "regex".
    flag_type = db.Column(db.String(16), default="static", nullable=False)
    content = db.Column(db.Text, nullable=False)
    # Weight is a percentage 0-100. Sum across a challenge's flags should be 100
    # (enforced in the admin API, not the DB — admins can save invalid states
    # while drafting).
    weight = db.Column(db.Integer, default=100, nullable=False)
    label = db.Column(db.String(128))  # display label, e.g. "Root flag"

    challenge = db.relationship("Challenges", foreign_keys="EdoFlag.challenge_id")


class EdoFlagSolve(db.Model):
    """
    Per-team record of which flags of a multi-flag challenge have been solved.

    We track solves at flag granularity so partial credit works: a team that
    finds 2 of 3 flags gets 2/3 of the challenge points.
    """

    __tablename__ = "edo_flag_solves"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), nullable=False, index=True
    )
    flag_id = db.Column(
        db.Integer, db.ForeignKey("edo_flags.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Attribution: user or team, matching CTFd's user_mode.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id", ondelete="CASCADE"), index=True)
    solved_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        # Same team can only solve a given flag once.
        db.UniqueConstraint("team_id", "flag_id", name="uq_edo_flag_solve_team"),
        db.UniqueConstraint("user_id", "flag_id", name="uq_edo_flag_solve_user"),
    )


class EdoInstance(db.Model):
    """
    One running container for one (challenge, team) pair.

    Uniqueness constraint enforces the "one dedicated container per challenge
    per team" rule. The daemon is authoritative for `status`; the plugin
    updates the DB after each RPC and the reconciler heals drift.
    """

    __tablename__ = "edo_instances"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), nullable=False, index=True
    )
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id", ondelete="CASCADE"), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True)

    # Daemon-side identifiers. container_id is None until the spawn RPC returns.
    container_id = db.Column(db.String(64), unique=True)
    container_name = db.Column(db.String(128))
    # Where the participant connects. Populated once the daemon reports back.
    host_ip = db.Column(db.String(64))
    host_ports = db.Column(db.String(256))  # CSV: "31337/tcp,8080/tcp"

    status = db.Column(db.String(24), default="pending", nullable=False)
    # status ∈ {pending, running, expired, stopped, error, orphaned}

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    last_reconciled_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)

    __table_args__ = (
        db.UniqueConstraint(
            "challenge_id", "team_id", name="uq_edo_instance_team_chal"
        ),
        db.UniqueConstraint(
            "challenge_id", "user_id", name="uq_edo_instance_user_chal"
        ),
    )


class EdoVPNPeer(db.Model):
    """A WireGuard peer bound to a user or a team."""

    __tablename__ = "edo_vpn_peers"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True, unique=True
    )
    team_id = db.Column(
        db.Integer, db.ForeignKey("teams.id", ondelete="CASCADE"), index=True
    )
    public_key = db.Column(db.String(64), nullable=False)
    # Private key is stored so the user can re-download their .conf. If your
    # threat model forbids this, generate client-side and store only the pubkey.
    private_key = db.Column(db.String(64), nullable=False)
    assigned_ip = db.Column(db.String(64), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    revoked = db.Column(db.Boolean, default=False, nullable=False)


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
