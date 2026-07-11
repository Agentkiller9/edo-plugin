"""
Background workers: TTL monitor + daemon/DB reconciler.

We use APScheduler's BackgroundScheduler — it ships with CTFd's deps in most
deployments; if not, `pip install apscheduler` is required. Both jobs use the
same coalescing config so if a worker is asleep, we don't stack up runs.

Important lifecycle note:
    Flask-SQLAlchemy sessions are request-scoped by default. Inside these
    background jobs there is no request context, so we push the Flask app
    context manually. Every job MUST close its session at the end or the
    connection pool leaks.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler

from .config import EdoConfig
from .daemon_client import DaemonError, EdoDaemonClient
from .models import EdoAuditLog, EdoInstance, EdoSettings, db

logger = logging.getLogger("edo.scheduler")

_scheduler: BackgroundScheduler | None = None


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

    scheduler.add_job(
        lambda: _run_with_app(app, _sweep_expired),
        "interval", seconds=ttl_interval, id="edo.ttl_sweep",
    )
    scheduler.add_job(
        lambda: _run_with_app(app, _reconcile),
        "interval", seconds=recon_interval, id="edo.reconcile",
    )

    scheduler.start()
    _scheduler = scheduler
    logger.info("edo scheduler started (ttl=%ss, reconcile=%ss)", ttl_interval, recon_interval)
    return scheduler


def stop_scheduler():
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def _run_with_app(app, fn):
    with app.app_context():
        try:
            fn()
        except Exception:
            logger.exception("edo job %s failed", fn.__name__)
        finally:
            db.session.remove()


def _client() -> EdoDaemonClient:
    return EdoDaemonClient(
        socket_path=EdoConfig.DAEMON_SOCKET_PATH,
        hmac_key=EdoConfig.DAEMON_HMAC_KEY,
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
                client.container_teardown(inst.container_id)
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
        live = {row["container_id"]: row for row in client.container_list()}
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
        if cid not in tracked_ids and row.get("challenge_id"):
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
