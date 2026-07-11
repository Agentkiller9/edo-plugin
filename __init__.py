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

from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import CHALLENGE_CLASSES
from CTFd.plugins.migrations import upgrade

from .api import edo_bp
from .challenge_type import EdoChallengeType
from .config import EdoConfig
from .models import EdoSettings, db
from .scheduler import start_scheduler

logger = logging.getLogger("edo")


def load(app):
    plugin_dir = os.path.dirname(__file__)

    # 1. Migrations (creates our tables if not present).
    upgrade(plugin_name="edo-plugin")

    # 2. Register challenge type.
    CHALLENGE_CLASSES["edo"] = EdoChallengeType

    # 3. Blueprint at /plugins/edo/*
    app.register_blueprint(edo_bp, url_prefix="/plugins/edo")

    # 4. Assets — templates AND static files.
    register_plugin_assets_directory(
        app, base_path="/plugins/edo-plugin/assets/"
    )

    # 5. Seed defaults on first boot. Idempotent — never clobbers admin edits.
    with app.app_context():
        _seed_defaults()

    # 6. Background workers.
    #    Guard against gunicorn --preload double-start: only the "master" env
    #    we detect via WORKER_ID being unset should skip; workers should each
    #    start their own scheduler and rely on APScheduler's per-process
    #    coalescing. If your deployment prefers a singleton, gate this on
    #    os.environ.get("EDO_SCHEDULER_ENABLED") == "1" and set it on ONE
    #    worker only.
    start_scheduler(app)

    logger.info("edo-plugin loaded (daemon=%s)", EdoConfig.DAEMON_SOCKET_PATH)


def _seed_defaults():
    defaults = {
        "max_containers_per_team":    EdoConfig.DEFAULT_MAX_CONTAINERS_PER_TEAM,
        "container_ttl_seconds":      EdoConfig.DEFAULT_CONTAINER_TTL_SECONDS,
        "extend_seconds":             EdoConfig.DEFAULT_EXTEND_SECONDS,
        "extend_threshold_seconds":   EdoConfig.DEFAULT_EXTEND_THRESHOLD_SECONDS,
        "submit_rate_limit":          EdoConfig.DEFAULT_SUBMIT_RATE_LIMIT,
        "submit_rate_window":         EdoConfig.DEFAULT_SUBMIT_RATE_WINDOW,
        "vpn_subnet":                 EdoConfig.DEFAULT_VPN_SUBNET,
        "vpn_server_endpoint":        EdoConfig.DEFAULT_VPN_SERVER_ENDPOINT,
        "reconcile_interval_seconds": EdoConfig.DEFAULT_RECONCILE_INTERVAL_SECONDS,
        "ttl_check_interval_seconds": EdoConfig.DEFAULT_TTL_CHECK_INTERVAL_SECONDS,
    }
    for k, v in defaults.items():
        if EdoSettings.query.filter_by(key=k).first() is None:
            db.session.add(EdoSettings(key=k, value=str(v)))
    db.session.commit()
