"""
Small decorators used across the edo-plugin API surface.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from functools import wraps
from threading import Lock

from flask import jsonify, request
from CTFd.models import Teams, Users
from CTFd.utils.user import get_current_team, get_current_user

# In-process token bucket. This is intentionally simple: CTFd may run under
# multiple workers, so this is a *soft* limit — the daemon-side rate limit
# in the edo-daemon is the real cap. If you need a hard cluster-wide limit,
# swap this for a Redis-backed sliding window.
_LOCK = Lock()
_BUCKETS: dict[tuple, deque[float]] = defaultdict(deque)


def rate_limited(key_fn, limit: int, window: int):
    """
    Per-key rate limiter. `key_fn(request)` returns a tuple key.

    Args:
        key_fn: callable(request) -> hashable
        limit:  max requests per window
        window: window length in seconds
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = key_fn(request)
            now = time.monotonic()
            cutoff = now - window
            with _LOCK:
                bucket = _BUCKETS[key]
                while bucket and bucket[0] < cutoff:
                    bucket.popleft()
                if len(bucket) >= limit:
                    retry = int(window - (now - bucket[0])) + 1
                    return (
                        jsonify(
                            success=False,
                            error="rate_limited",
                            retry_after=retry,
                        ),
                        429,
                    )
                bucket.append(now)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def submit_rate_key(_request):
    """Key flag-submissions by (team-or-user, challenge_id)."""
    team = get_current_team()
    user = get_current_user()
    principal = ("team", team.id) if team else ("user", user.id if user else 0)
    # challenge_id is in the view kwargs or JSON body depending on route.
    body = _request.get_json(silent=True) or {}
    chal = body.get("challenge_id") or _request.view_args.get("challenge_id")
    return principal + ("chal", chal)


def team_required(fn):
    """
    Reject unauthenticated calls, and in team-mode, calls without a team.

    Anything that spawns containers or issues VPN configs must resolve to a
    team so the isolation subnet lookup works.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return jsonify(success=False, error="not_authenticated"), 401
        from CTFd.utils import get_config
        if get_config("user_mode") == "teams" and get_current_team() is None:
            return jsonify(success=False, error="team_required"), 400
        return fn(*args, **kwargs)
    return wrapper


def get_principal_ids() -> tuple[int, int | None]:
    """Return (user_id, team_id) for the current requester."""
    user = get_current_user()
    team = get_current_team()
    return user.id, (team.id if team else None)
