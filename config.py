"""
edo-plugin configuration.

Values here are compile-time defaults. Runtime-adjustable values live in the
EdoSettings table and can be edited from the admin UI. The socket path is a
startup concern and belongs in an env var; there's no shared secret to
configure anymore — the daemon authenticates callers via SO_PEERCRED (the
kernel-verified UID of the connecting process), not an application-layer key.
"""
import os


class EdoConfig:
    # ---- Daemon transport ----
    # Unix socket exposed by edo-daemon running as root. Must match
    # EDO_SOCKET_PATH in the daemon's own environment (they're two different
    # processes/env spaces pointing at the same bind-mounted path).
    DAEMON_SOCKET_PATH = os.environ.get("EDO_DAEMON_SOCKET", "/run/edo/edo.sock")
    # Per-RPC timeout in seconds. A first spawn of a challenge builds its
    # image from scratch (no layer cache yet) — keep this generous enough
    # to cover a real first build, not just a trivial test Dockerfile.
    # Later spawns of the same challenge reuse cached layers and return in
    # a couple seconds regardless of this value.
    DAEMON_RPC_TIMEOUT = int(os.environ.get("EDO_DAEMON_TIMEOUT", "180"))

    # ---- Defaults for EdoSettings on first boot ----
    DEFAULT_MAX_CONTAINERS_PER_OWNER = 3
    DEFAULT_CONTAINER_TTL_SECONDS = 60 * 60           # 1 hour
    DEFAULT_EXTEND_SECONDS = 30 * 60                  # +30 min
    DEFAULT_EXTEND_THRESHOLD_SECONDS = 10 * 60        # button unlocks under 10 min
    DEFAULT_SUBMIT_RATE_LIMIT = 10                    # attempts per window
    DEFAULT_SUBMIT_RATE_WINDOW = 60                   # seconds
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
