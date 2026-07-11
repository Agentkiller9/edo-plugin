"""
Background workers: TTL monitor + daemon/DB reconciler.

We use APScheduler's BackgroundScheduler — it ships with CTFd's deps in most
deployments; if not, `pip install apscheduler` is required. Both jobs use the
same coalescing config so if a worker is asleep, we don't stack up runs.

CTFd typically runs multiple gunicorn workers, and start_scheduler(app) is
called once per worker process — naively, that means N schedulers all
sweeping/reconciling independently. Both jobs are idempotent (a double
teardown or double reconcile is harmless), but running them N times is
wasteful and N-times more daemon RPC traffic for no benefit. Instead, each
tick first tries to win a lease row (EdoWorkerLease) before doing any real
work; only the worker holding the lease for that lock proceeds. See
_try_acquire_lease().

Important lifecycle note:
    Flask-SQLAlchemy sessions are request-scoped by default. Inside these
    background jobs there is no request context, so we push the Flask app
    context manually. Every job MUST close its session at the end or the
    connection pool leaks.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.exc import IntegrityError

from .config import EdoConfig
from .daemon_client import DaemonError, EdoDaemonClient
from .models import EdoAuditLog, EdoInstance, EdoSettings, EdoWorkerLease, db

logger = logging.getLogger("edo.scheduler")

_scheduler: BackgroundScheduler | None = None

# Unique per process — every gunicorn worker gets its own on import. Good
# enough for leader election even though it's not a stable identity across
# restarts; a fresh id just means a fresh worker starts uncontested.
_WORKER_ID = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"


def start_scheduler(app):
    """Wire jobs against the given Flask app. Idempotent; safe under gunicorn."""
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    scheduler = BackgroundScheduler(
        job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 30}
    )

    ttl_interval = int(EdoSettings.get(
        "ttl_check_interval_seconds",
        default=EdoConfig.DEFAULT_TTL_CHECK_INTERVAL_SECONDS,
        cast=int,
    ) or EdoConfig.DEFAULT_TTL_CHECK_INTERVAL_SECONDS)
    recon_interval = int(EdoSettings.get(
        "reconcile_interval_seconds",
        default=EdoConfig.DEFAULT_RECONCILE_INTERVAL_SECONDS,
        cast=int,
    ) or EdoConfig.DEFAULT_RECONCILE_INTERVAL_SECONDS)

    # Lease outlives its own interval by 3x so the current leader's next
    # tick renews it well before it lapses; if the leader process dies, a
    # new leader takes over within one lease window at most.
    scheduler.add_job(
        lambda: _run_with_app(app, _sweep_expired, "edo.ttl_sweep", ttl_interval * 3),
        "interval", seconds=ttl_interval, id="edo.ttl_sweep",
    )
    scheduler.add_job(
        lambda: _run_with_app(app, _reconcile, "edo.reconcile", recon_interval * 3),
        "interval", seconds=recon_interval, id="edo.reconcile",
    )

    scheduler.start()
    _scheduler = scheduler
    logger.info(
        "edo scheduler started (worker=%s, ttl=%ss, reconcile=%ss)",
        _WORKER_ID, ttl_interval, recon_interval,
    )
    return scheduler


def stop_scheduler():
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def _try_acquire_lease(lock_name: str, lease_seconds: int) -> bool:
    """
    Win (or renew) the named lease for this worker.

    Returns True if this worker may proceed this tick. Uses a conditional
    UPDATE first (works whether we already hold it or it's expired), falling
    back to an INSERT if the row doesn't exist yet — the INSERT's unique
    primary key means at most one concurrent worker wins a brand-new lock.
    """
    now = datetime.utcnow()
    new_expiry = now + timedelta(seconds=max(lease_seconds, 10))

    matched = EdoWorkerLease.query.filter(
        EdoWorkerLease.lock_name == lock_name,
        db.or_(EdoWorkerLease.expires_at < now, EdoWorkerLease.holder == _WORKER_ID),
    ).update(
        {"holder": _WORKER_ID, "expires_at": new_expiry, "updated_at": now},
        synchronize_session=False,
    )
    if matched:
        db.session.commit()
        return True

    if EdoWorkerLease.query.filter_by(lock_name=lock_name).first() is not None:
        # Row exists and is currently held by someone else, unexpired.
        db.session.rollback()
        return False

    try:
        db.session.add(EdoWorkerLease(
            lock_name=lock_name, holder=_WORKER_ID,
            expires_at=new_expiry, updated_at=now,
        ))
        db.session.commit()
        return True
    except IntegrityError:
        # Another worker's INSERT landed first — they're leader this tick.
        db.session.rollback()
        return False


def _run_with_app(app, fn, lock_name: str, lease_seconds: int):
    with app.app_context():
        try:
            if not _try_acquire_lease(lock_name, lease_seconds):
                return
            fn()
        except Exception:
            logger.exception("edo job %s failed", fn.__name__)
        finally:
            db.session.remove()


def _client() -> EdoDaemonClient:
    return EdoDaemonClient(
        socket_path=EdoConfig.DAEMON_SOCKET_PATH,
        timeout=EdoConfig.DAEMON_RPC_TIMEOUT,
    )


# ---------- TTL sweep ----------

def _sweep_expired():
    """Teardown any instance whose expires_at is in the past."""
    now = datetime.utcnow()
    expired = (
        EdoInstance.query
        .filter(EdoInstance.expires_at <= now)
        .filter(EdoInstance.status.in_(("pending", "running")))
        .all()
    )
    if not expired:
        return

    client = _client()
    for inst in expired:
        try:
            if inst.container_id:
                client.container_release_instance(inst.container_id)
            inst.status = "expired"
            _audit("scheduler", "teardown_expired", inst)
        except DaemonError as e:
            inst.status = "error"
            inst.error_message = f"teardown failed: {e}"
            _audit("scheduler", "teardown_failed", inst, {"error": str(e)})
    db.session.commit()


# ---------- Reconciliation ----------

def _reconcile():
    """
    Reconcile DB state with daemon truth.

    Rules:
    - DB says running but daemon doesn't know it -> mark 'orphaned'.
    - Daemon has a container the DB doesn't -> log it; don't touch it (admin
      might be inspecting manually).
    - Daemon status disagrees with DB -> update DB to match.
    """
    client = _client()
    try:
        result = client.container_reconcile()
        live = {row["container_id"]: row for row in result.get("instances", [])}
    except DaemonError as e:
        logger.warning("reconcile: daemon unreachable: %s", e)
        return

    tracked = EdoInstance.query.filter(
        EdoInstance.status.in_(("pending", "running"))
    ).all()

    tracked_ids = set()
    for inst in tracked:
        if not inst.container_id:
            # Spawn RPC never returned; leave alone unless well past TTL.
            continue
        tracked_ids.add(inst.container_id)
        live_row = live.get(inst.container_id)
        inst.last_reconciled_at = datetime.utcnow()

        if live_row is None:
            inst.status = "orphaned"
            inst.error_message = "container missing on host at reconcile"
            _audit("reconciler", "orphan_detected", inst)
        elif live_row.get("status") not in ("running", "created"):
            inst.status = "stopped"
            _audit("reconciler", "container_stopped", inst,
                   {"daemon_status": live_row.get("status")})

    # Note un-tracked live containers (won't kill — could be admin manual).
    for cid, row in live.items():
        if cid not in tracked_ids and row.get("challenge_ref"):
            _audit("reconciler", "untracked_container", None,
                   {"container_id": cid, "raw": row})

    db.session.commit()


def _audit(actor: str, event: str, inst: EdoInstance | None, details: dict | None = None):
    db.session.add(EdoAuditLog(
        actor=actor,
        event=event,
        challenge_id=inst.challenge_id if inst else None,
        instance_id=inst.id if inst else None,
        details=json.dumps(details) if details else None,
    ))
