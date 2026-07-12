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

from CTFd.models import Challenges, Flags, Solves, db
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
            "build_path",
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
            "build_path",
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
    # CTFd's /api/v1/challenges/attempt view only calls attempt() at all
    # when the account has NO existing Solves row for this challenge
    # (`if not solves:` — checked in CTFd core, not here). The instant a
    # Solves row exists, EVERY future submission — including a genuinely
    # different, still-unfound flag — gets short-circuited into
    # "already_solved" without ever reaching this class again.
    #
    # That means a multi-flag challenge CANNOT insert a Solves row on the
    # first correct flag, or every later flag becomes unsubmittable. CTFd
    # anticipates exactly this with a third attempt() outcome beyond
    # correct/incorrect: returning ("partial", message) calls partial()
    # instead of solve() and skips the Solves insert, so the account can
    # keep submitting. Only once every flag is found does attempt() return
    # a real "correct", which finally calls solve() and inserts the Solves
    # row — CTFd's scoreboard sums Challenges.value per Solve with no
    # concept of a fractional award, so a flag's weight_pct can only ever
    # be a progress/display figure (see owner_progress()), not literal
    # partial points on the scoreboard — full value is awarded once, when
    # the last flag completes the set.

    @classmethod
    def attempt(cls, challenge, request):
        """
        Try to match the submission against one of the challenge's flags.

        Returns (True, msg) once ALL flags are found (triggers solve()),
        ("partial", msg) when a NEW flag is found but others remain
        (triggers partial() — no Solves row, so submission stays open),
        or (False, msg) otherwise.
        """
        from .config import EdoConfig
        from .decorators import check_rate_limit
        from .models import EdoSettings
        from .owner import resolve_owner

        owner = resolve_owner()
        if owner is not None:
            limit = int(EdoSettings.get(
                "submit_rate_limit", default=EdoConfig.DEFAULT_SUBMIT_RATE_LIMIT, cast=int
            ) or EdoConfig.DEFAULT_SUBMIT_RATE_LIMIT)
            window = int(EdoSettings.get(
                "submit_rate_window", default=EdoConfig.DEFAULT_SUBMIT_RATE_WINDOW, cast=int
            ) or EdoConfig.DEFAULT_SUBMIT_RATE_WINDOW)
            key = owner + ("chal", challenge.id)
            allowed, retry_after = check_rate_limit(key, limit, window)
            if not allowed:
                return False, f"Rate limited — try again in {retry_after}s"

        data = request.form or request.get_json() or {}
        submission = (data.get("submission") or "").strip()
        if not submission:
            return False, "Empty submission"

        flag = _first_matching_flag(challenge.id, submission)
        if flag is None:
            return False, "Incorrect"

        if owner is None:
            # Shouldn't happen (spawning/etc. all require a resolved
            # owner), but attempt() is reachable via CTFd's own endpoint
            # regardless of our route decorators — fail closed.
            return False, "Incorrect"
        owner_type, owner_id = owner

        if EdoFlagSolve.query.filter_by(
            owner_type=owner_type, owner_id=owner_id, flag_id=flag.id
        ).first():
            return "partial", "You already found this flag"

        total_flags = Flags.query.filter_by(challenge_id=challenge.id).count()
        found_so_far = EdoFlagSolve.query.filter_by(
            owner_type=owner_type, owner_id=owner_id, challenge_id=challenge.id
        ).count()
        if found_so_far + 1 >= total_flags:
            return True, "Correct! All flags captured."
        return "partial", f"Correct! {found_so_far + 1}/{total_flags} flags found."

    @classmethod
    def partial(cls, user, team, challenge, request):
        """
        Called by CTFd when attempt() returns "partial" — a real flag was
        found but the challenge isn't fully solved yet. Records the flag
        find WITHOUT touching CTFd's Solves table, so the account can keep
        submitting the remaining flags (see the class-level note above for
        why inserting a Solve here would lock further submissions out).
        """
        cls._record_flag_solve(user, team, challenge, request)

    @classmethod
    def solve(cls, user, team, challenge, request):
        """
        Called by CTFd once attempt() returns a real "correct" — the LAST
        flag needed to complete the challenge. Records that flag AND
        inserts the CTFd Solve row, which is what the scoreboard reads.
        """
        cls._record_flag_solve(user, team, challenge, request)

        owner_id = team.id if team else user.id
        already_solved = Solves.query.filter_by(
            challenge_id=challenge.id,
            **({"team_id": owner_id} if team else {"user_id": owner_id}),
        ).first()
        if already_solved is None:
            data = request.form or request.get_json() or {}
            submission = (data.get("submission") or "").strip()
            db.session.add(Solves(
                user_id=user.id,
                team_id=team.id if team else None,
                challenge_id=challenge.id,
                ip=request.access_route[0] if request.access_route else request.remote_addr,
                provided=submission,
            ))
        db.session.commit()

    @classmethod
    def _record_flag_solve(cls, user, team, challenge, request):
        """Shared by partial() and solve(): record this owner having found
        this specific flag, idempotently."""
        data = request.form or request.get_json() or {}
        submission = (data.get("submission") or "").strip()
        flag = _first_matching_flag(challenge.id, submission)
        if flag is None:
            # attempt() said yes but nothing matched — race with a flag
            # edit between attempt() and this call. Bail cleanly.
            return

        owner_type = "team" if team is not None else "user"
        owner_id = team.id if team is not None else user.id

        if EdoFlagSolve.query.filter_by(
            owner_type=owner_type, owner_id=owner_id, flag_id=flag.id
        ).first():
            return

        db.session.add(EdoFlagSolve(
            challenge_id=challenge.id,
            flag_id=flag.id,
            owner_type=owner_type,
            owner_id=owner_id,
        ))
        db.session.commit()

    @classmethod
    def fail(cls, user, team, challenge, request):
        # CTFd's default fails-table insert already fires — this hook is a
        # place to add extra bookkeeping if we wanted (e.g. streak breakers).
        pass

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
