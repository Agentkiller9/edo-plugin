"""
Custom challenge type registration.

Two things happen here:
1. `EdoChallengeType` — the Python class CTFd looks up when the frontend picks
   the 'edo' challenge type. It handles read/create/update/attempt/solve.
2. Registration of asset paths so CTFd serves our JS/CSS/templates.
"""
from __future__ import annotations

import json
import re
from typing import Any

from CTFd.models import Challenges, Solves, db
from CTFd.plugins.challenges import CHALLENGE_CLASSES, BaseChallenge
from CTFd.plugins.migrations import upgrade
from CTFd.utils.modes import get_model
from CTFd.utils.user import get_current_team, get_current_user

from .models import EdoChallenge, EdoFlag, EdoFlagSolve


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
        challenge = EdoChallenge(**{
            k: v for k, v in data.items()
            if k in {
                "name", "description", "category", "value",
                "difficulty", "scoring_mode",
                "initial_value", "minimum_value", "decay",
                "docker_image", "exposed_ports",
                "cpu_limit", "memory_limit_mb", "pids_limit",
                "ttl_seconds",
            }
        })
        db.session.add(challenge)
        db.session.commit()
        return challenge

    @classmethod
    def read(cls, challenge):
        # Include current dynamic value so the view template can render decay.
        challenge = EdoChallenge.query.filter_by(id=challenge.id).first()
        flags = EdoFlag.query.filter_by(challenge_id=challenge.id).all()
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
            "docker_image": challenge.docker_image,
            "exposed_ports": challenge.exposed_ports,
            "cpu_limit": challenge.cpu_limit,
            "memory_limit_mb": challenge.memory_limit_mb,
            "pids_limit": challenge.pids_limit,
            "ttl_seconds": challenge.ttl_seconds,
            "flags": [
                {
                    "id": f.id,
                    "label": f.label,
                    "flag_type": f.flag_type,
                    "weight": f.weight,
                }
                for f in flags
            ],
        }

    @classmethod
    def update(cls, challenge, request):
        data = request.form or request.get_json() or {}
        editable = {
            "name", "description", "category", "value", "state", "max_attempts",
            "difficulty", "scoring_mode",
            "initial_value", "minimum_value", "decay",
            "docker_image", "exposed_ports",
            "cpu_limit", "memory_limit_mb", "pids_limit",
            "ttl_seconds",
        }
        for key, val in data.items():
            if key in editable:
                setattr(challenge, key, val)
        db.session.commit()
        return challenge

    @classmethod
    def delete(cls, challenge):
        # Cascade removes EdoFlag / EdoFlagSolve / EdoInstance via FK ON DELETE.
        Challenges.query.filter_by(id=challenge.id).delete()
        db.session.commit()

    # ---------- Attempt / Solve ----------

    @classmethod
    def attempt(cls, challenge, request) -> tuple[bool, str]:
        """
        Try to solve one of the challenge's flags.

        Returns (correct, message). CTFd calls this from the /api/v1/challenges/attempt
        pathway. We don't award points here — CTFd's Solves table does that via
        the value returned by `read().value`.
        """
        data = request.form or request.get_json() or {}
        submission = (data.get("submission") or "").strip()
        if not submission:
            return False, "Empty submission"

        flags = EdoFlag.query.filter_by(challenge_id=challenge.id).all()
        for flag in flags:
            if _flag_matches(flag, submission):
                return True, f"Correct! ({flag.label or 'flag'})"
        return False, "Incorrect"

    @classmethod
    def solve(cls, user, team, challenge, request):
        """
        Called by CTFd once `attempt()` returns True. We record BOTH a CTFd
        Solve (so the scoreboard picks it up) and an EdoFlagSolve row (so
        partial credit and multi-flag progress work).
        """
        data = request.form or request.get_json() or {}
        submission = (data.get("submission") or "").strip()

        flag = _first_matching_flag(challenge.id, submission)
        if flag is None:
            # attempt() said yes but nothing matched — race with a flag edit.
            # Bail cleanly rather than double-solving.
            return

        # Idempotency: never record the same (team/user, flag) solve twice.
        existing_q = EdoFlagSolve.query.filter_by(flag_id=flag.id)
        if team is not None:
            existing_q = existing_q.filter_by(team_id=team.id)
        else:
            existing_q = existing_q.filter_by(user_id=user.id)
        if existing_q.first() is not None:
            return

        db.session.add(EdoFlagSolve(
            challenge_id=challenge.id,
            flag_id=flag.id,
            team_id=team.id if team else None,
            user_id=user.id,
        ))

        # Only insert a CTFd Solve row on the *first* correct flag for this
        # (principal, challenge). Subsequent flags top up the value the
        # scoreboard reads via `read().value`.
        Model = get_model()
        principal_id = team.id if team else user.id
        already_solved = Solves.query.filter_by(
            challenge_id=challenge.id,
            **({"team_id": principal_id} if team else {"user_id": principal_id}),
        ).first()
        if already_solved is None:
            solve = Solves(
                user_id=user.id,
                team_id=team.id if team else None,
                challenge_id=challenge.id,
                ip=request.access_route[0] if request.access_route else request.remote_addr,
                provided=submission,
            )
            db.session.add(solve)
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
        # This is the maximum. Per-team achieved value is base * sum(weights of
        # solved flags) / 100 and is computed at rendering / scoreboard time.
        return base


def _flag_matches(flag: EdoFlag, submission: str) -> bool:
    if flag.flag_type == "regex":
        try:
            return re.match(flag.content, submission) is not None
        except re.error:
            return False
    return submission == flag.content


def _first_matching_flag(challenge_id: int, submission: str) -> EdoFlag | None:
    for f in EdoFlag.query.filter_by(challenge_id=challenge_id).all():
        if _flag_matches(f, submission):
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
