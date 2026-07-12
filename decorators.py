"""
Small decorators + rate-limit primitive used across the edo-plugin API
surface.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from functools import wraps
from threading import Lock
from typing import Tuple

from flask import jsonify
from CTFd.utils.user import get_current_user

from .owner import resolve_owner

# In-process token bucket. This is intentionally simple: CTFd may run under
# multiple workers, so this is a *soft* limit — the daemon-side rate limit
# in the edo-daemon is the real cap. If you need a hard cluster-wide limit,
# swap this for a Redis-backed sliding window.
_LOCK = Lock()
_BUCKETS: dict[tuple, deque[float]] = defaultdict(deque)


def check_rate_limit(key: tuple, limit: int, window: int) -> Tuple[bool, int]:
    """
    Returns (allowed, retry_after_seconds). Called directly from
    EdoChallengeType.attempt() so the limit is enforced no matter which
    endpoint a submission comes through (CTFd's native
    /api/v1/challenges/attempt calls attempt() itself — there's no
    separate custom submission route to gate anymore).
    """
    now = time.monotonic()
    cutoff = now - window
    with _LOCK:
        bucket = _BUCKETS[key]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            retry = int(window - (now - bucket[0])) + 1
            return False, retry
        bucket.append(now)
    return True, 0


def owner_required(fn):
    """
    Reject unauthenticated calls, and in team-mode, calls from a user who
    hasn't joined/created a team yet.

    Anything that spawns containers or issues VPN configs must resolve to
    an owner so the isolation subnet lookup works.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if get_current_user() is None:
            return jsonify(success=False, error="not_authenticated"), 401
        if resolve_owner() is None:
            return jsonify(success=False, error="team_required"), 400
        return fn(*args, **kwargs)
    return wrapper
