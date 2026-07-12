"""
Participant-facing routes.

Every mutating route enforces:
    - authenticated + owner resolvable (owner_required covers both)
    - global per-owner container cap
    - one-container-per-(challenge, owner) uniqueness (DB unique constraint)

Flag submission (submit_flag, below) is the PRIMARY path for edo challenges
— not CTFd's native /api/v1/challenges/attempt. See the docstring on
EdoChallengeType's attempt()/solve() in challenge_type.py for why: CTFd
3.7.5 has no "partial credit" concept, so multi-flag progress has to be
owned entirely by this route instead of CTFd's native dispatcher.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta

from flask import Blueprint, Response, jsonify, render_template, request
from CTFd.models import Fails, Teams, Users, db
from CTFd.utils.decorators import authed_only

from ..config import EdoConfig
from ..daemon_client import DaemonError, EdoDaemonClient
from ..decorators import check_rate_limit, owner_required
from ..models import EdoAuditLog, EdoChallenge, EdoFlagSolve, EdoInstance, EdoPeer, EdoSettings
from ..owner import current_user_id, resolve_owner

logger = logging.getLogger("edo.api.user")

user_bp = Blueprint("edo_user", __name__, template_folder="../templates")


def _client() -> EdoDaemonClient:
    return EdoDaemonClient(
        socket_path=EdoConfig.DAEMON_SOCKET_PATH,
        timeout=EdoConfig.DAEMON_RPC_TIMEOUT,
    )


def _setting(key, default, cast=int):
    return EdoSettings.get(key, default=default, cast=cast) or default


# ---------- Dashboard ----------

@user_bp.route("/dashboard", methods=["GET"])
@authed_only
def dashboard_page():
    return render_template("user/edo_dashboard.html")


@user_bp.route("/dashboard/data", methods=["GET"])
@authed_only
@owner_required
def dashboard_data():
    owner_type, owner_id = resolve_owner()
    instances = (
        EdoInstance.query
        .filter(EdoInstance.status.in_(("pending", "running")))
        .filter_by(owner_type=owner_type, owner_id=owner_id)
        .all()
    )

    extend_threshold = _setting(
        "extend_threshold_seconds", EdoConfig.DEFAULT_EXTEND_THRESHOLD_SECONDS
    )
    max_containers = _setting(
        "max_containers_per_owner", EdoConfig.DEFAULT_MAX_CONTAINERS_PER_OWNER
    )

    return jsonify(
        success=True,
        max_containers=max_containers,
        extend_threshold_seconds=extend_threshold,
        instances=[_serialize_instance(i, extend_threshold) for i in instances],
    )


@user_bp.route("/challenges/<int:challenge_id>/progress", methods=["GET"])
@authed_only
@owner_required
def challenge_progress(challenge_id: int):
    """Weighted multi-flag progress for the current owner on one challenge."""
    from ..challenge_type import owner_progress

    owner_type, owner_id = resolve_owner()
    return jsonify(success=True, **owner_progress(challenge_id, owner_type, owner_id))


# ---------- Container lifecycle ----------

@user_bp.route("/challenges/<int:challenge_id>/instance", methods=["POST"])
@authed_only
@owner_required
def spawn_instance(challenge_id: int):
    owner_type, owner_id = resolve_owner()
    challenge = EdoChallenge.query.get(challenge_id)
    if challenge is None:
        return jsonify(success=False, error="challenge_not_found"), 404
    if not challenge.build_path:
        return jsonify(success=False, error="challenge_has_no_build_path"), 400

    # Enforce cap. Reserving the EdoInstance row below is what actually
    # closes the double-click race (DB unique constraint) — this count is
    # just the friendly "you're at your limit" check.
    max_containers = _setting(
        "max_containers_per_owner", EdoConfig.DEFAULT_MAX_CONTAINERS_PER_OWNER
    )
    active_count = (
        EdoInstance.query
        .filter(EdoInstance.status.in_(("pending", "running")))
        .filter_by(owner_type=owner_type, owner_id=owner_id)
        .count()
    )
    if active_count >= max_containers:
        return jsonify(success=False, error="owner_container_limit", limit=max_containers), 429

    ttl = int(challenge.ttl_seconds or _setting(
        "container_ttl_seconds", EdoConfig.DEFAULT_CONTAINER_TTL_SECONDS
    ))
    expires_at = datetime.utcnow() + timedelta(seconds=ttl)
    inst = EdoInstance(
        challenge_id=challenge_id,
        owner_type=owner_type,
        owner_id=owner_id,
        expires_at=expires_at,
        status="pending",
    )
    db.session.add(inst)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        existing = EdoInstance.query.filter_by(
            challenge_id=challenge_id, owner_type=owner_type, owner_id=owner_id
        ).first()
        if existing:
            return jsonify(success=False, error="already_running", instance_id=existing.id), 409
        return jsonify(success=False, error="race_conflict"), 409

    try:
        result = _client().container_ensure_instance(
            owner_type=owner_type,
            owner_id=owner_id,
            challenge_ref=str(challenge_id),
            build_path=challenge.build_path,
            security={
                "cpus": float(challenge.cpu_limit or 1.0),
                "memory": f"{int(challenge.memory_limit_mb or 512)}m",
                "pids_limit": int(challenge.pids_limit or 256),
                "read_only_rootfs": bool(challenge.read_only_rootfs),
            },
            ttl_seconds=ttl,
        )
    except DaemonError as e:
        # Delete rather than mark "error": unlike a teardown failure (where
        # a real container may still be running and worth an admin's
        # attention), a spawn failure means nothing was ever created —
        # there's no infrastructure state to investigate, only a row that
        # would otherwise permanently occupy the UNIQUE constraint on
        # (challenge_id, owner_type, owner_id) and block every retry.
        # _audit() first so the failure is still visible in the audit log
        # (EdoAuditLog.instance_id isn't a real FK, so it survives the
        # delete below).
        _audit("user", "spawn_failed", inst, {"error": str(e)})
        db.session.delete(inst)
        db.session.commit()
        return jsonify(success=False, error="daemon_error", detail=str(e)), 502

    inst.container_id   = result.get("container_id")
    inst.container_name = result.get("container_name")
    inst.assigned_ip     = result.get("assigned_ip")
    inst.host_ports      = json.dumps(result.get("ports") or [])
    inst.status          = "running"
    _audit("user", "spawn", inst)
    db.session.commit()

    return jsonify(success=True, instance=_serialize_instance(inst, _setting(
        "extend_threshold_seconds", EdoConfig.DEFAULT_EXTEND_THRESHOLD_SECONDS
    )))


@user_bp.route("/instances/<int:instance_id>", methods=["DELETE"])
@authed_only
@owner_required
def teardown_instance(instance_id: int):
    inst, err = _owned_instance(instance_id)
    if err:
        return err
    try:
        if inst.container_id:
            _client().container_release_instance(inst.container_id)
    except DaemonError as e:
        # Best-effort: still remove the row so the owner isn't permanently
        # locked out of respawning (see note on the unique constraint
        # below). The daemon's own spawn is idempotent by (owner,
        # challenge_ref), and the reconciler heals any drift if the
        # container is somehow still alive despite this RPC failing.
        logger.warning("teardown RPC failed for instance %s: %s", instance_id, e)
    _audit("user", "teardown", inst)
    # Delete rather than mark "stopped": the UNIQUE constraint on
    # (challenge_id, owner_type, owner_id) applies to every row regardless
    # of status, so a soft-stopped row would permanently block that owner
    # from ever spawning this challenge again. History lives in the audit
    # log (written just above); EdoInstance only ever tracks what's live.
    db.session.delete(inst)
    db.session.commit()
    return jsonify(success=True)


@user_bp.route("/instances/<int:instance_id>/extend", methods=["POST"])
@authed_only
@owner_required
def extend_instance(instance_id: int):
    inst, err = _owned_instance(instance_id)
    if err:
        return err

    threshold = _setting(
        "extend_threshold_seconds", EdoConfig.DEFAULT_EXTEND_THRESHOLD_SECONDS
    )
    extend_by = _setting("extend_seconds", EdoConfig.DEFAULT_EXTEND_SECONDS)
    remaining = (inst.expires_at - datetime.utcnow()).total_seconds()
    if remaining > threshold:
        return jsonify(
            success=False, error="not_yet_extendable",
            remaining_seconds=int(remaining),
            threshold_seconds=threshold,
        ), 400

    inst.expires_at = inst.expires_at + timedelta(seconds=extend_by)
    _audit("user", "extend", inst, {"added_seconds": extend_by})
    db.session.commit()
    return jsonify(success=True, expires_at=inst.expires_at.isoformat())


# ---------- WireGuard ----------

@user_bp.route("/vpn", methods=["GET"])
@authed_only
def vpn_page():
    return render_template("user/edo_vpn.html")


@user_bp.route("/vpn/config", methods=["GET"])
@authed_only
@owner_required
def download_wg_config():
    """
    Return a WireGuard .conf for the current user. Lazily provisions a peer
    the first time. VPN identity is always per-user (even in team mode);
    owner_type/owner_id just tag which container subnet this peer may reach.
    """
    user_id = current_user_id()
    owner_type, owner_id = resolve_owner()
    peer_row = EdoPeer.query.filter_by(user_id=user_id, revoked=False).first()
    client = _client()

    if peer_row is None:
        try:
            peer = client.wg_ensure_peer(user_id=user_id, owner_type=owner_type, owner_id=owner_id)
        except DaemonError as e:
            return jsonify(success=False, error="daemon_error", detail=str(e)), 502
        peer_row = EdoPeer(
            user_id=user_id,
            owner_type=owner_type,
            owner_id=owner_id,
            public_key=peer["public_key"],
            private_key=peer.get("private_key"),
            assigned_ip=peer["assigned_ip"],
        )
        db.session.add(peer_row)
        db.session.commit()

    try:
        blob = client.wg_render_config(user_id)
    except DaemonError as e:
        return jsonify(success=False, error="daemon_error", detail=str(e)), 502

    username = Users.query.get(user_id).name
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", username) or f"user-{user_id}"
    resp = Response(blob, mimetype="text/plain")
    resp.headers["Content-Disposition"] = f'attachment; filename="{safe_name}.conf"'
    return resp


# ---------- Flag submission ----------

@user_bp.route("/challenges/<int:challenge_id>/submit", methods=["POST"])
@authed_only
@owner_required
def submit_flag(challenge_id: int):
    """
    Primary submission path for edo challenges (see module docstring for
    why this exists instead of using CTFd's native attempt endpoint).

    Every correct-but-incomplete flag is recorded as real progress
    (EdoFlagSolve) immediately — nothing here waits for the set to
    complete before crediting an individual flag find. Only the final,
    set-completing flag also inserts CTFd's own Solves row, which is what
    actually awards scoreboard points.
    """
    owner_type, owner_id = resolve_owner()
    challenge = EdoChallenge.query.get(challenge_id)
    if challenge is None:
        return jsonify(success=False, error="challenge_not_found"), 404

    limit = _setting("submit_rate_limit", EdoConfig.DEFAULT_SUBMIT_RATE_LIMIT)
    window = _setting("submit_rate_window", EdoConfig.DEFAULT_SUBMIT_RATE_WINDOW)
    allowed, retry_after = check_rate_limit(
        (owner_type, owner_id, "submit", challenge_id), limit, window
    )
    if not allowed:
        return jsonify(
            success=False, error="rate_limited", retry_after=retry_after
        ), 429

    user = Users.query.get(current_user_id())
    team = Teams.query.get(owner_id) if owner_type == "team" else None
    owner_filter = {"team_id": owner_id} if team else {"user_id": owner_id}

    if challenge.max_attempts:
        fail_count = Fails.query.filter_by(challenge_id=challenge_id, **owner_filter).count()
        if fail_count >= challenge.max_attempts:
            return jsonify(success=False, error="attempts_exhausted"), 403

    data = request.get_json(silent=True) or request.form or {}
    submission = (data.get("submission") or "").strip()
    if not submission:
        return jsonify(success=False, error="empty_submission"), 400

    from ..challenge_type import (
        _first_matching_flag, _insert_ctfd_fail, _insert_ctfd_solve,
        owner_progress, record_flag_find,
    )

    ip = request.access_route[0] if request.access_route else request.remote_addr

    flag = _first_matching_flag(challenge_id, submission)
    if flag is None:
        _insert_ctfd_fail(challenge, user, team, submission, ip=ip)
        return jsonify(success=True, correct=False, message="Incorrect")

    already_found = EdoFlagSolve.query.filter_by(
        owner_type=owner_type, owner_id=owner_id, flag_id=flag.id
    ).first()
    if already_found is not None:
        progress = owner_progress(challenge_id, owner_type, owner_id)
        return jsonify(
            success=True, correct=True, already_found=True,
            complete=progress["flags_solved"] >= progress["flags_total"],
            message="You already found this flag.",
            **progress,
        )

    record_flag_find(challenge_id, user, team, submission)
    progress = owner_progress(challenge_id, owner_type, owner_id)

    complete = progress["flags_solved"] >= progress["flags_total"]
    if complete:
        _insert_ctfd_solve(challenge, user, team, submission, ip=ip)
        message = "Correct! Challenge complete."
    else:
        remaining = progress["flags_total"] - progress["flags_solved"]
        message = f"Correct! {remaining} flag(s) remaining."

    return jsonify(success=True, correct=True, complete=complete, message=message, **progress)


# ---------- helpers ----------

def _owned_instance(instance_id: int):
    """Load an instance and verify the caller's owner matches. Returns (inst, error_response)."""
    owner_type, owner_id = resolve_owner()
    inst = EdoInstance.query.get(instance_id)
    if inst is None:
        return None, (jsonify(success=False, error="not_found"), 404)
    if inst.owner_type != owner_type or inst.owner_id != owner_id:
        return None, (jsonify(success=False, error="forbidden"), 403)
    return inst, None


def _serialize_instance(i: EdoInstance, extend_threshold: int) -> dict:
    now = datetime.utcnow()
    remaining = int((i.expires_at - now).total_seconds()) if i.expires_at else 0
    return {
        "id": i.id,
        "challenge_id": i.challenge_id,
        "container_name": i.container_name,
        "assigned_ip": i.assigned_ip,
        "host_ports": i.host_ports,
        "status": i.status,
        "expires_at": i.expires_at.isoformat() if i.expires_at else None,
        "remaining_seconds": max(remaining, 0),
        "can_extend": 0 < remaining <= extend_threshold,
    }


def _audit(actor: str, event: str, inst: EdoInstance | None, details: dict | None = None):
    db.session.add(EdoAuditLog(
        actor=actor,
        event=event,
        challenge_id=inst.challenge_id if inst else None,
        instance_id=inst.id if inst else None,
        details=json.dumps(details) if details else None,
    ))
