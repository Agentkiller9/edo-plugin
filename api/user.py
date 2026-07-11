"""
Participant-facing routes.

Every mutating route enforces:
    - authenticated (team_required covers this and team-mode)
    - global per-team container cap
    - one-container-per-(challenge, team) uniqueness (DB unique constraint)
    - rate limits for flag submission (belt on top of daemon-side belt)
"""
from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timedelta

from flask import Blueprint, Response, jsonify, render_template, request
from CTFd.models import db
from CTFd.utils.decorators import authed_only

from ..config import EdoConfig
from ..daemon_client import DaemonError, EdoDaemonClient
from ..decorators import (
    get_principal_ids,
    rate_limited,
    submit_rate_key,
    team_required,
)
from ..models import (
    EdoAuditLog,
    EdoChallenge,
    EdoInstance,
    EdoSettings,
    EdoVPNPeer,
)

logger = logging.getLogger("edo.api.user")

user_bp = Blueprint("edo_user", __name__, template_folder="../templates")


def _client() -> EdoDaemonClient:
    return EdoDaemonClient(
        socket_path=EdoConfig.DAEMON_SOCKET_PATH,
        hmac_key=EdoConfig.DAEMON_HMAC_KEY,
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
@team_required
def dashboard_data():
    user_id, team_id = get_principal_ids()
    q = EdoInstance.query.filter(EdoInstance.status.in_(("pending", "running")))
    if team_id is not None:
        q = q.filter(EdoInstance.team_id == team_id)
    else:
        q = q.filter(EdoInstance.user_id == user_id)
    instances = q.all()

    extend_threshold = _setting(
        "extend_threshold_seconds", EdoConfig.DEFAULT_EXTEND_THRESHOLD_SECONDS
    )
    max_containers = _setting(
        "max_containers_per_team", EdoConfig.DEFAULT_MAX_CONTAINERS_PER_TEAM
    )

    return jsonify(
        success=True,
        max_containers=max_containers,
        extend_threshold_seconds=extend_threshold,
        instances=[_serialize_instance(i, extend_threshold) for i in instances],
    )


# ---------- Container lifecycle ----------

@user_bp.route("/challenges/<int:challenge_id>/instance", methods=["POST"])
@authed_only
@team_required
def spawn_instance(challenge_id: int):
    user_id, team_id = get_principal_ids()
    challenge = EdoChallenge.query.get(challenge_id)
    if challenge is None:
        return jsonify(success=False, error="challenge_not_found"), 404
    if not challenge.docker_image:
        return jsonify(success=False, error="challenge_has_no_image"), 400

    # Enforce cap. Use FOR UPDATE-style: count in a fresh query inside a
    # transaction so a fast double-click can't punch past the cap. Postgres
    # will actually serialize this; SQLite is single-writer so it's moot.
    max_containers = _setting(
        "max_containers_per_team", EdoConfig.DEFAULT_MAX_CONTAINERS_PER_TEAM
    )
    active_q = EdoInstance.query.filter(EdoInstance.status.in_(("pending", "running")))
    if team_id is not None:
        active_q = active_q.filter(EdoInstance.team_id == team_id)
    else:
        active_q = active_q.filter(EdoInstance.user_id == user_id)
    active_count = active_q.count()
    if active_count >= max_containers:
        return jsonify(
            success=False, error="team_container_limit",
            limit=max_containers,
        ), 429

    # Reserve the row first (satisfies the (challenge, team) unique constraint
    # atomically). If someone else already reserved it we'll bounce.
    ttl = int(challenge.ttl_seconds or _setting(
        "container_ttl_seconds", EdoConfig.DEFAULT_CONTAINER_TTL_SECONDS
    ))
    expires_at = datetime.utcnow() + timedelta(seconds=ttl)
    inst = EdoInstance(
        challenge_id=challenge_id,
        team_id=team_id,
        user_id=user_id,
        expires_at=expires_at,
        status="pending",
    )
    db.session.add(inst)
    try:
        db.session.commit()
    except Exception:
        # IntegrityError from the unique constraint — surface the existing one.
        db.session.rollback()
        existing = active_q.filter(EdoInstance.challenge_id == challenge_id).first()
        if existing:
            return jsonify(
                success=False, error="already_running", instance_id=existing.id
            ), 409
        return jsonify(success=False, error="race_conflict"), 409

    # Ask the daemon to actually spawn it.
    try:
        result = _client().container_spawn(
            challenge_id=challenge_id,
            team_id=team_id,
            user_id=user_id,
            image=challenge.docker_image,
            exposed_ports=(challenge.exposed_ports or "").split(",") if challenge.exposed_ports else [],
            cpu_limit=float(challenge.cpu_limit or 1.0),
            memory_mb=int(challenge.memory_limit_mb or 512),
            pids_limit=int(challenge.pids_limit or 256),
            ttl_seconds=ttl,
        )
    except DaemonError as e:
        inst.status = "error"
        inst.error_message = str(e)
        _audit("user", "spawn_failed", inst, {"error": str(e)})
        db.session.commit()
        return jsonify(success=False, error="daemon_error", detail=str(e)), 502

    inst.container_id   = result.get("container_id")
    inst.container_name = result.get("container_name")
    inst.host_ip        = result.get("host_ip")
    inst.host_ports     = result.get("host_ports")
    inst.status         = "running"
    _audit("user", "spawn", inst)
    db.session.commit()

    return jsonify(success=True, instance=_serialize_instance(inst))


@user_bp.route("/instances/<int:instance_id>", methods=["DELETE"])
@authed_only
@team_required
def teardown_instance(instance_id: int):
    inst, err = _owned_instance(instance_id)
    if err:
        return err
    try:
        if inst.container_id:
            _client().container_teardown(inst.container_id)
    except DaemonError as e:
        # Best-effort: still mark stopped so it stops counting against quota.
        inst.error_message = f"teardown_failed: {e}"
    inst.status = "stopped"
    _audit("user", "teardown", inst)
    db.session.commit()
    return jsonify(success=True)


@user_bp.route("/instances/<int:instance_id>/extend", methods=["POST"])
@authed_only
@team_required
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

@user_bp.route("/vpn/config", methods=["GET"])
@authed_only
def download_wg_config():
    """
    Return a WireGuard .conf for the current user. Lazily provisions a peer
    the first time.
    """
    user_id, team_id = get_principal_ids()
    peer_row = EdoVPNPeer.query.filter_by(user_id=user_id, revoked=False).first()
    client = _client()

    if peer_row is None:
        try:
            peer = client.wg_generate_peer(user_id=user_id, team_id=team_id)
        except DaemonError as e:
            return jsonify(success=False, error="daemon_error", detail=str(e)), 502
        peer_row = EdoVPNPeer(
            user_id=user_id,
            team_id=team_id,
            public_key=peer["public_key"],
            private_key=peer["private_key"],
            assigned_ip=peer["assigned_ip"],
        )
        db.session.add(peer_row)
        db.session.commit()

    try:
        blob = client.wg_render_config({
            "public_key":  peer_row.public_key,
            "private_key": peer_row.private_key,
            "assigned_ip": peer_row.assigned_ip,
        })
    except DaemonError as e:
        return jsonify(success=False, error="daemon_error", detail=str(e)), 502

    resp = Response(blob, mimetype="text/plain")
    resp.headers["Content-Disposition"] = f'attachment; filename="edo-user-{user_id}.conf"'
    return resp


# ---------- Flag submission (rate-limited) ----------

@user_bp.route("/challenges/<int:challenge_id>/submit", methods=["POST"])
@authed_only
@team_required
@rate_limited(
    submit_rate_key,
    limit=EdoConfig.DEFAULT_SUBMIT_RATE_LIMIT,
    window=EdoConfig.DEFAULT_SUBMIT_RATE_WINDOW,
)
def submit_flag(challenge_id: int):
    """
    Thin proxy that hands the submission to CTFd's own /api/v1/challenges/attempt
    once we've rate-limited it. Keeping the endpoint here means the rate limit
    lives in *our* code, not CTFd core — and it fires before CTFd's cheaper
    checks so we don't burn cycles on abusers.

    The real matching happens in EdoChallengeType.attempt(); we defer to it.
    """
    from ..challenge_type import EdoChallengeType
    challenge = EdoChallenge.query.get(challenge_id)
    if challenge is None:
        return jsonify(success=False, error="challenge_not_found"), 404

    correct, message = EdoChallengeType.attempt(challenge, request)
    if not correct:
        return jsonify(success=True, correct=False, message=message)

    user_id, team_id = get_principal_ids()
    from CTFd.models import Teams, Users
    user = Users.query.get(user_id)
    team = Teams.query.get(team_id) if team_id else None
    EdoChallengeType.solve(user, team, challenge, request)
    return jsonify(success=True, correct=True, message=message)


# ---------- helpers ----------

def _owned_instance(instance_id: int):
    """Load an instance and verify the caller owns it. Returns (inst, error_response)."""
    user_id, team_id = get_principal_ids()
    inst = EdoInstance.query.get(instance_id)
    if inst is None:
        return None, (jsonify(success=False, error="not_found"), 404)
    if team_id is not None:
        if inst.team_id != team_id:
            return None, (jsonify(success=False, error="forbidden"), 403)
    else:
        if inst.user_id != user_id:
            return None, (jsonify(success=False, error="forbidden"), 403)
    return inst, None


def _serialize_instance(i: EdoInstance, extend_threshold: int) -> dict:
    now = datetime.utcnow()
    remaining = int((i.expires_at - now).total_seconds()) if i.expires_at else 0
    return {
        "id": i.id,
        "challenge_id": i.challenge_id,
        "container_name": i.container_name,
        "host_ip": i.host_ip,
        "host_ports": i.host_ports,
        "status": i.status,
        "expires_at": i.expires_at.isoformat() if i.expires_at else None,
        "remaining_seconds": max(remaining, 0),
        "can_extend": 0 < remaining <= extend_threshold,
    }


def _audit(actor: str, event: str, inst: EdoInstance | None, details: dict | None = None):
    db.session.add(EdoAuditLog(
        actor=f"{actor}:{inst.user_id}" if inst else actor,
        event=event,
        challenge_id=inst.challenge_id if inst else None,
        instance_id=inst.id if inst else None,
        details=json.dumps(details) if details else None,
    ))
