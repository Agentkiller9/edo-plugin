"""
Custom challenge type registration.

Two things happen here:
1. `EdoChallengeType` — the Python class CTFd looks up when the frontend picks
   the 'edo' challenge type. It handles read/create/update/attempt/solve.
2. Registration of asset paths so CTFd serves our JS/CSS/templates.

Flags are CTFd's own native Flags table — NOT a reimplementation. CTFd's
admin challenge-edit UI already renders a generic "Flags" tab (add/edit/
delete, regex vs static, case sensitivity) for every challenge type,
working purely off challenge_id via /api/v1/flags. Reinventing that would
throw away flag-type plugins, import/export, and that whole UI for
nothing. The ONLY new table here is EdoFlagWeight, which attaches a
percentage-of-value to each native flag — everything else (content,
type, comparison) goes through CTFd's own get_flag_class().compare().
"""
from __future__ import annotations

from typing import Any, Optional

from CTFd.models import Challenges, Fails, Flags, Solves, db
from CTFd.plugins.challenges import CHALLENGE_CLASSES, BaseChallenge
from CTFd.plugins.flags import get_flag_class

from .models import EdoChallenge, EdoFlagSolve, EdoFlagWeight

_INT_FIELDS = {
    "value", "initial_value", "minimum_value", "decay",
    "memory_limit_mb", "pids_limit", "ttl_seconds",
    "max_attempts", "position",
}
_FLOAT_FIELDS = {"cpu_limit"}
_BOOL_FIELDS = {"read_only_rootfs"}


def _coerce_field(key: str, val):
    """
    Form/JSON submissions from CTFd's admin JS always arrive as strings
    (or, for a JSON body, sometimes native bools) — the frontend has no
    idea our columns are typed. An empty string for an optional numeric
    field (e.g. a blank TTL override) would otherwise get inserted as ''
    into an INTEGER column, which MariaDB's strict mode rejects with an
    unhandled exception — a bare 500 with no useful message — rather than
    a friendly validation error.
    """
    if key in _INT_FIELDS:
        if val in (None, ""):
            return None
        try:
            return int(val)
        except (TypeError, ValueError):
            return None
    if key in _FLOAT_FIELDS:
        if val in (None, ""):
            return None
        try:
            return float(val)
        except (TypeError, ValueError):
            return None
    if key in _BOOL_FIELDS:
        if isinstance(val, bool):
            return val
        return str(val).lower() in ("true", "1", "on", "yes")
    return val


class EdoChallengeType(BaseChallenge):
    id = "edo"
    name = "edo"
    templates = {
        "create": "/plugins/edo_plugin/assets/create.html",
        "update": "/plugins/edo_plugin/assets/update.html",
        "view":   "/plugins/edo_plugin/assets/view.html",
    }
    scripts = {
        "create": "/plugins/edo_plugin/assets/create.js",
        "update": "/plugins/edo_plugin/assets/update.js",
        "view":   "/plugins/edo_plugin/assets/view.js",
    }
    route = "/plugins/edo_plugin/assets/"
    blueprint = None  # blueprint is registered in __init__.py so we don't double-register
    challenge_model = EdoChallenge

    # ---------- CRUD ----------

    @classmethod
    def create(cls, request):
        data = request.form or request.get_json() or {}
        fields = {
            "name", "description", "category", "value", "state", "attribution",
            "difficulty", "scoring_mode",
            "initial_value", "minimum_value", "decay",
            "build_path", "access_mode",
            "cpu_limit", "memory_limit_mb", "pids_limit",
            "read_only_rootfs", "ttl_seconds",
        }
        challenge = EdoChallenge(**{
            k: _coerce_field(k, v) for k, v in data.items() if k in fields
        })
        db.session.add(challenge)
        db.session.commit()
        return challenge

    @classmethod
    def read(cls, challenge):
        challenge = EdoChallenge.query.filter_by(id=challenge.id).first()
        return {
            "id": challenge.id,
            "name": challenge.name,
            "value": cls._current_value(challenge),
            "description": challenge.description,
            "category": challenge.category,
            "state": challenge.state,
            "max_attempts": challenge.max_attempts,
            "type": challenge.type,
            "type_data": {
                "id": cls.id,
                "name": cls.name,
                "templates": cls.templates,
                "scripts": cls.scripts,
            },
            "difficulty": challenge.difficulty,
            "scoring_mode": challenge.scoring_mode,
            "initial_value": challenge.initial_value,
            "minimum_value": challenge.minimum_value,
            "decay": challenge.decay,
            "build_path": challenge.build_path,
            "access_mode": challenge.access_mode,
            "cpu_limit": challenge.cpu_limit,
            "memory_limit_mb": challenge.memory_limit_mb,
            "pids_limit": challenge.pids_limit,
            "read_only_rootfs": challenge.read_only_rootfs,
            "ttl_seconds": challenge.ttl_seconds,
        }

    @classmethod
    def update(cls, challenge, request):
        data = request.form or request.get_json() or {}
        editable = {
            "name", "description", "category", "value", "state", "max_attempts",
            "attribution", "connection_info", "position",
            "difficulty", "scoring_mode",
            "initial_value", "minimum_value", "decay",
            "build_path", "access_mode",
            "cpu_limit", "memory_limit_mb", "pids_limit",
            "read_only_rootfs", "ttl_seconds",
        }
        for key, val in data.items():
            if key in editable:
                setattr(challenge, key, _coerce_field(key, val))
        db.session.commit()
        return challenge

    @classmethod
    def delete(cls, challenge):
        # Cascade removes EdoFlagSolve / EdoInstance via FK ON DELETE.
        # EdoFlagWeight cascades transitively through Flags' own FK to
        # challenges, since EdoFlagWeight.flag_id -> flags.id ON DELETE CASCADE.
        Challenges.query.filter_by(id=challenge.id).delete()
        db.session.commit()

    # ---------- Attempt / Solve ----------
    #
    # IMPORTANT — verified against the actual deployed CTFd 3.7.5 source
    # (NOT the docs, NOT CTFd's `master` branch, which is ahead of this
    # pinned version): CTFd 3.7.5's /api/v1/challenges/attempt dispatcher
    # does a plain Python truthiness check —
    #
    #     status, message = chal_class.attempt(challenge, request)
    #     if status:                       # ANY non-empty/non-False value
    #         chal_class.solve(...)        # -> Solves row inserted NOW
    #
    # — and only calls attempt() at all `if not solves:` for this account.
    # There is no "partial" status in this version (that's a `master`-only
    # feature we don't have). So: the FIRST truthy attempt() result
    # permanently inserts a Solves row and blocks every future submission
    # for that challenge, full stop — there is no way to represent "correct
    # flag, but the challenge isn't done yet" through CTFd's native
    # endpoint on this version.
    #
    # Consequently, multi-flag submission for edo challenges is NOT routed
    # through CTFd's native attempt endpoint at all — participants submit
    # via /plugins/edo_plugin/challenges/<id>/submit (api/user.py), which
    # owns the real per-flag matching/progress/completion logic directly.
    # attempt()/solve() below are kept only as a safe fallback for the
    # admin "preview" flag-tester and any direct API caller: attempt()
    # only ever returns truthy when the submission is BOTH a real flag AND
    # the one that completes the full set for this owner, so hitting the
    # native endpoint directly can never under-award (skip a flag) or
    # over-award (full credit for a partial find).
    #
    # Either way, full challenge value is awarded exactly once, when the
    # last flag completes the set — CTFd's scoreboard sums Challenges.value
    # per Solve with no per-solve override, so a flag's weight_pct can only
    # ever be a progress/display figure (see owner_progress()), never
    # literal partial points added to the scoreboard mid-way.

    @classmethod
    def attempt(cls, challenge, request) -> tuple[bool, str]:
        owner_type, owner_id = _resolve_owner_or_none()
        if owner_type is None:
            return False, "Incorrect"

        data = request.form or request.get_json() or {}
        submission = (data.get("submission") or "").strip()
        if not submission:
            return False, "Empty submission"

        flag = _first_matching_flag(challenge.id, submission)
        if flag is None:
            return False, "Incorrect"

        if EdoFlagSolve.query.filter_by(
            owner_type=owner_type, owner_id=owner_id, flag_id=flag.id
        ).first():
            # Already credited — don't let the native fallback re-trigger
            # anything (real progress is only ever recorded via the
            # dedicated /submit route, see class docstring above).
            return False, "Incorrect"

        total_flags = Flags.query.filter_by(challenge_id=challenge.id).count()
        found_so_far = EdoFlagSolve.query.filter_by(
            owner_type=owner_type, owner_id=owner_id, challenge_id=challenge.id
        ).count()
        if found_so_far + 1 >= total_flags:
            return True, "Correct! All flags captured."
        return False, f"Correct, but {total_flags - found_so_far - 1} flag(s) remain — submit from the challenge panel."

    @classmethod
    def solve(cls, user, team, challenge, request):
        """Only reached when attempt() returned True — i.e. this genuinely
        is the flag that completes the set for this owner."""
        data = request.form or request.get_json() or {}
        submission = (data.get("submission") or "").strip()
        ip = request.access_route[0] if request.access_route else request.remote_addr
        record_flag_find(challenge.id, user, team, submission)
        _insert_ctfd_solve(challenge, user, team, submission, ip=ip)

    @classmethod
    def fail(cls, user, team, challenge, request):
        """Only reached via the native-endpoint fallback (see class
        docstring above) — the primary /submit route logs its own Fails
        rows directly via _insert_ctfd_fail()."""
        data = request.form or request.get_json() or {}
        submission = (data.get("submission") or "").strip()
        ip = request.access_route[0] if request.access_route else request.remote_addr
        _insert_ctfd_fail(challenge, user, team, submission, ip=ip)

    # ---------- Scoring ----------

    @classmethod
    def _current_value(cls, challenge: EdoChallenge) -> int:
        """Total points *available* right now for this challenge."""
        if challenge.scoring_mode == "static":
            base = challenge.value or 0
        else:
            base = _dynamic_value(challenge)
        # This is the maximum. Per-owner achieved value is base * sum(weights
        # of solved flags) / 100 and is computed at rendering / scoreboard time.
        return base


def _first_matching_flag(challenge_id: int, submission: str) -> Optional[Flags]:
    for f in Flags.query.filter_by(challenge_id=challenge_id).all():
        if get_flag_class(f.type).compare(f, submission):
            return f
    return None


def _resolve_owner_or_none() -> tuple:
    from .owner import resolve_owner
    owner = resolve_owner()
    return owner if owner is not None else (None, None)


def record_flag_find(challenge_id: int, user, team, submission: str) -> Optional[Flags]:
    """
    Idempotently record that this owner found this specific flag. Shared
    by the primary /submit route (api/user.py) and the native-endpoint
    fallback's solve(). Returns the matched Flags row, or None if the
    submission no longer matches anything (e.g. a flag was deleted between
    the caller's own check and this call).
    """
    flag = _first_matching_flag(challenge_id, submission)
    if flag is None:
        return None

    owner_type = "team" if team is not None else "user"
    owner_id = team.id if team is not None else user.id

    if not EdoFlagSolve.query.filter_by(
        owner_type=owner_type, owner_id=owner_id, flag_id=flag.id
    ).first():
        db.session.add(EdoFlagSolve(
            challenge_id=challenge_id,
            flag_id=flag.id,
            owner_type=owner_type,
            owner_id=owner_id,
        ))
        db.session.commit()
    return flag


def _insert_ctfd_solve(challenge, user, team, submission: str, ip: str = "") -> None:
    """Insert CTFd's own Solves row (idempotent) — this is what the
    scoreboard actually reads. Call only once the full flag set is
    complete for this owner."""
    owner_id = team.id if team else user.id
    already_solved = Solves.query.filter_by(
        challenge_id=challenge.id,
        **({"team_id": owner_id} if team else {"user_id": owner_id}),
    ).first()
    if already_solved is None:
        db.session.add(Solves(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=ip,
            provided=submission,
        ))
        db.session.commit()


def _insert_ctfd_fail(challenge, user, team, submission: str, ip: str = "") -> None:
    """Insert CTFd's own Fails row so wrong guesses still show up in the
    admin Submissions log and count toward max_attempts, matching what the
    native attempt endpoint would have recorded."""
    db.session.add(Fails(
        user_id=user.id,
        team_id=team.id if team else None,
        challenge_id=challenge.id,
        ip=ip,
        provided=submission,
    ))
    db.session.commit()


def _dynamic_value(challenge: EdoChallenge) -> int:
    """Linear decay from initial_value → minimum_value over `decay` solves."""
    solve_count = Solves.query.filter_by(challenge_id=challenge.id).count()
    initial = challenge.initial_value or challenge.value or 0
    minimum = challenge.minimum_value or 0
    decay = max(1, challenge.decay or 1)
    if solve_count >= decay:
        return minimum
    dropped = (initial - minimum) * (solve_count / decay)
    return int(round(initial - dropped))


def owner_progress(challenge_id: int, owner_type: str, owner_id: int) -> dict:
    """
    Weighted progress for one owner on a multi-flag challenge — the
    percentage of the challenge's current value they've earned so far, plus
    which flags are still outstanding. Used by the view template to show
    "2/3 flags captured" style progress.
    """
    flags = Flags.query.filter_by(challenge_id=challenge_id).all()
    weights = {
        w.flag_id: w.weight_pct
        for w in EdoFlagWeight.query.filter(
            EdoFlagWeight.flag_id.in_([f.id for f in flags])
        ).all()
    }
    solved_flag_ids = {
        s.flag_id
        for s in EdoFlagSolve.query.filter_by(
            challenge_id=challenge_id, owner_type=owner_type, owner_id=owner_id
        ).all()
    }
    total_weight = sum(weights.get(f.id, 100) for f in flags) or 100
    earned_weight = sum(weights.get(fid, 100) for fid in solved_flag_ids)
    return {
        "flags_total": len(flags),
        "flags_solved": len(solved_flag_ids),
        "percent_earned": round(100 * earned_weight / total_weight, 1) if total_weight else 0,
    }
