"""
edo-plugin configuration.

Values here are compile-time defaults. Runtime-adjustable values live in the
EdoSettings table and can be edited from the admin UI. Anything sensitive
(the HMAC key, socket path) is a startup concern and belongs in env vars.
"""
import os


class EdoConfig:
    # ---- Daemon transport ----
    # Unix socket exposed by edo-daemon running as root.
    DAEMON_SOCKET_PATH = os.environ.get("EDO_DAEMON_SOCKET", "/run/edo/edo-daemon.sock")
    # Shared secret used to HMAC-sign every RPC. Rotate by restarting both sides.
    DAEMON_HMAC_KEY = os.environ.get("EDO_DAEMON_HMAC_KEY", "").encode()
    # Per-RPC timeout in seconds. Docker spawns can be slow; keep generous.
    DAEMON_RPC_TIMEOUT = int(os.environ.get("EDO_DAEMON_TIMEOUT", "30"))

    # ---- Defaults for EdoSettings on first boot ----
    DEFAULT_MAX_CONTAINERS_PER_TEAM = 3
    DEFAULT_CONTAINER_TTL_SECONDS = 60 * 60           # 1 hour
    DEFAULT_EXTEND_SECONDS = 30 * 60                  # +30 min
    DEFAULT_EXTEND_THRESHOLD_SECONDS = 10 * 60        # button unlocks under 10 min
    DEFAULT_SUBMIT_RATE_LIMIT = 10                    # attempts per window
    DEFAULT_SUBMIT_RATE_WINDOW = 60                   # seconds
    DEFAULT_VPN_SUBNET = "10.9.0.0/24"
    DEFAULT_VPN_SERVER_ENDPOINT = "vpn.example.com:51820"
    DEFAULT_RECONCILE_INTERVAL_SECONDS = 60
    DEFAULT_TTL_CHECK_INTERVAL_SECONDS = 15

    # ---- Difficulty tiers exposed to the UI ----
    DIFFICULTIES = [
        {"key": "easy",      "label": "Easy",      "color": "#28a745"},  # green
        {"key": "medium",    "label": "Medium",    "color": "#ffc107"},  # yellow
        {"key": "hard",      "label": "Hard",      "color": "#dc3545"},  # red
        {"key": "very_hard", "label": "Very Hard", "color": "#6f42c1"},  # purple
    ]
    DIFFICULTY_KEYS = {d["key"] for d in DIFFICULTIES}
