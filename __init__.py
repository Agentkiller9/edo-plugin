"""
edo-plugin — CTFd master plugin entry point.

CTFd calls `load(app)` once at boot. That is our single opportunity to:

    1. Run/verify DB migrations for our custom tables.
    2. Register EdoChallenge as a challenge type CTFd knows about.
    3. Mount the /plugins/edo blueprint (admin + user routes).
    4. Serve template/asset files at the paths CTFd expects.
    5. Seed default EdoSettings rows so admins don't stare at NULLs.
    6. Start the background scheduler (TTL sweep + reconciler).

Everything privileged happens over a Unix socket to edo-daemon — the CTFd
worker itself never touches iptables, Docker, or wg-quick.
"""
from __future__ import annotations

import logging
import os

from CTFd.plugins import register_plugin_assets_directory, register_user_page_menu_bar
from CTFd.plugins.challenges import CHALLENGE_CLASSES

from .api import edo_bp
from .challenge_type import EdoChallengeType
from .config import EdoConfig
from .models import (
    EdoAuditLog, EdoChallenge, EdoFlagSolve, EdoFlagWeight,
    EdoInstance, EdoPeer, EdoSettings, EdoWorkerLease, db,
)
from .scheduler import start_scheduler

logger = logging.getLogger("edo")


def load(app):
    # 1. Create our tables. `upgrade(plugin_name=...)` only runs Alembic
    #    revisions (or db.create_all() on SQLite) — since we're a brand-new
    #    plugin with no migrations directory, we create our tables directly.
    #    `create_all` is a no-op for tables that already exist, so it's safe
    #    to run on every boot.
    with app.app_context():
        db.metadata.create_all(bind=db.engine, tables=[
            EdoChallenge.__table__,
            EdoFlagWeight.__table__,
            EdoFlagSolve.__table__,
            EdoInstance.__table__,
            EdoPeer.__table__,
            EdoSettings.__table__,
            EdoAuditLog.__table__,
            EdoWorkerLease.__table__,
        ])

    # 2. Register challenge type.
    CHALLENGE_CLASSES["edo"] = EdoChallengeType

    # 3. Blueprint at /plugins/edo_plugin/* — matches the folder name so all
    #    URL prefixes stay consistent with CTFd convention.
    app.register_blueprint(edo_bp, url_prefix="/plugins/edo_plugin")

    # 4. Assets served statically at /plugins/edo_plugin/assets/*.
    register_plugin_assets_directory(
        app, base_path="/plugins/edo_plugin/assets/"
    )

    # Nav bar link to the VPN page. register_user_page_menu_bar builds its
    # href via url_for("views.static_html", route=...), whose URL rule is
    # just `/<path:route>` — so this resolves to the plain path
    # "/plugins/edo_plugin/vpn" at render time. That path is also a real
    # route on our own blueprint (registered above), and Werkzeug always
    # prefers a specific static-segment match over the catch-all
    # `<path:route>` Pages view, so it's our page that actually serves it,
    # not CTFd's Pages system.
    register_user_page_menu_bar(title="VPN", route="plugins/edo_plugin/vpn")

    # 5. Seed defaults on first boot. Idempotent — never clobbers admin edits.
    with app.app_context():
        _seed_defaults()

    # 6. Background workers.
    #    Every gunicorn worker calls start_scheduler(), so every worker runs
    #    its own APScheduler instance — but scheduler.py's jobs only do real
    #    work on the one worker that currently holds the EdoWorkerLease row
    #    for that job. See scheduler.py's module docstring.
    start_scheduler(app)

    logger.info("edo-plugin loaded (daemon=%s)", EdoConfig.DAEMON_SOCKET_PATH)


def _seed_defaults():
    defaults = {
        "max_containers_per_owner":   EdoConfig.DEFAULT_MAX_CONTAINERS_PER_OWNER,
        "container_ttl_seconds":      EdoConfig.DEFAULT_CONTAINER_TTL_SECONDS,
        "extend_seconds":             EdoConfig.DEFAULT_EXTEND_SECONDS,
        "extend_threshold_seconds":   EdoConfig.DEFAULT_EXTEND_THRESHOLD_SECONDS,
        "submit_rate_limit":          EdoConfig.DEFAULT_SUBMIT_RATE_LIMIT,
        "submit_rate_window":         EdoConfig.DEFAULT_SUBMIT_RATE_WINDOW,
        "vpn_server_endpoint":        EdoConfig.DEFAULT_VPN_SERVER_ENDPOINT,
        "reconcile_interval_seconds": EdoConfig.DEFAULT_RECONCILE_INTERVAL_SECONDS,
        "ttl_check_interval_seconds": EdoConfig.DEFAULT_TTL_CHECK_INTERVAL_SECONDS,
    }
    for k, v in defaults.items():
        if EdoSettings.query.filter_by(key=k).first() is None:
            db.session.add(EdoSettings(key=k, value=str(v)))
    db.session.commit()
