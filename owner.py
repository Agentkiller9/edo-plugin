"""
Owner resolution — the one place that decides "who does this request act on
behalf of" for both CTFd user-mode and team-mode.

Every owner-scoped table (EdoInstance, EdoFlagSolve, EdoPeer's owner_* pair)
and every daemon RPC that touches network/container isolation keys off the
(owner_type, owner_id) pair this module produces, rather than each call site
re-deriving its own team-vs-user branch.
"""
from __future__ import annotations

from typing import Optional, Tuple

from CTFd.utils import get_config
from CTFd.utils.modes import TEAMS_MODE
from CTFd.utils.user import get_current_team, get_current_user


def resolve_owner() -> Optional[Tuple[str, int]]:
    """Return (owner_type, owner_id) for the current request, or None.

    None means "can't resolve yet" — either nobody is logged in, or CTFd is
    in team-mode and the current user hasn't joined/created a team. Callers
    that require an owner (spawning an instance, requesting a VPN peer)
    should treat None as a 400, not attempt to proceed with a placeholder.
    """
    user = get_current_user()
    if user is None:
        return None

    if get_config("user_mode") == TEAMS_MODE:
        team = get_current_team()
        if team is None:
            return None
        return ("team", team.id)

    return ("user", user.id)


def resolve_owner_for_user(user) -> Optional[Tuple[str, int]]:
    """Same resolution as resolve_owner(), but for an explicit user object
    instead of the current request's session. Used by admin bulk actions
    that iterate every user rather than acting on the logged-in caller.
    """
    if user is None:
        return None
    if get_config("user_mode") == TEAMS_MODE:
        if not user.team_id:
            return None
        return ("team", user.team_id)
    return ("user", user.id)


def current_user_id() -> Optional[int]:
    """The actual CTFd user id — always per-individual, even in team mode.

    Used for VPN peer identity (every teammate keeps their own device/config)
    as opposed to owner_id, which is the CONTAINER-access scope (the team,
    in team mode).
    """
    user = get_current_user()
    return user.id if user else None


def owner_display_name(owner_type: str, owner_id: int) -> str:
    """Human-readable label for admin views (audit log, instance table)."""
    if owner_type == "team":
        from CTFd.models import Teams

        team = Teams.query.get(owner_id)
        return team.name if team else f"team#{owner_id}"
    from CTFd.models import Users

    user = Users.query.get(owner_id)
    return user.name if user else f"user#{owner_id}"
