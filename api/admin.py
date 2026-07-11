"""
Admin-only routes.

CTFd's `admins_only` decorator gates access; every response is JSON except
for the template-rendering routes at the top which serve HTML for the plugin
config page.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request
from CTFd.models import Teams, Users, db
from CTFd.utils.decorators import admins_only

from ..config import EdoConfig
from ..daemon_client import DaemonError, EdoDaemonClient
from ..models import (
    EdoAuditLog,
    EdoChallenge,
    EdoFlag,
    EdoInstance,
    EdoSettings,
    EdoVPNPeer,
)

logger = logging.getLogger("edo.api.admin")

admin_bp = Blueprint("edo_admin", __name__, template_folder="../templates")


def _client() -> EdoDaemonClient:
    return EdoDaemonClient(
        socket_path=EdoConfig.DAEMON_SOCKET_PATH,
        hmac_key=EdoConfig.DAEMON_HMAC_KEY,
        timeout=EdoConfig.DAEMON_RPC_TIMEOUT,
    )


# ---------- Config page ----------

@admin_bp.route("/settings", methods=["GET"])
@admins_only
def settings_page():
    diffs = EdoConfig.DIFFICULTIES
    known = {
        "max_containers_per_team": EdoConfig.DEFAULT_MAX_CONTAINERS_PER_TEAM,
        "container_ttl_seconds":   EdoConfig.DEFAULT_CONTAINER_TTL_SECONDS,
        "extend_seconds":          EdoConfig.DEFAULT_EXTEND_SECONDS,
        "extend_threshold_seconds": EdoConfig.DEFAULT_EXTEND_THRESHOLD_SECONDS,
        "submit_rate_limit":       EdoConfig.DEFAULT_SUBMIT_RATE_LIMIT,
        "submit_rate_window":      EdoConfig.DEFAULT_SUBMIT_RATE_WINDOW,
        "vpn_subnet":              EdoConfig.DEFAULT_VPN_SUBNET,
        "vpn_server_endpoint":     EdoConfig.DEFAULT_VPN_SERVER_ENDPOINT,
        "reconcile_interval_seconds": EdoConfig.DEFAULT_RECONCILE_INTERVAL_SECONDS,
        "ttl_check_interval_seconds": EdoConfig.DEFAULT_TTL_CHECK_INTERVAL_SECONDS,
    }
    values = {k: EdoSettings.get(k, default=v) for k, v in known.items()}
    return render_template(
        "admin/edo_settings.html",
        values=values, difficulties=diffs,
    )


@admin_bp.route("/settings", methods=["POST"])
@admins_only
def settings_save():
    payload = request.get_json() or {}
    allowed = {
        "max_containers_per_team", "container_ttl_seconds",
        "extend_seconds", "extend_threshold_seconds",
        "submit_rate_limit", "submit_rate_window",
        "vpn_subnet", "vpn_server_endpoint",
        "reconcile_interval_seconds", "ttl_check_interval_seconds",
    }
    for k, v in payload.items():
        if k in allowed:
            EdoSettings.set(k, v)
    return jsonify(success=True)


# ---------- Flags ----------

@admin_bp.route("/challenges/<int:challenge_id>/flags", methods=["GET"])
@admins_only
def list_flags(challenge_id: int):
    flags = EdoFlag.query.filter_by(challenge_id=challenge_id).all()
    return jsonify(success=True, flags=[
        {
            "id": f.id, "label": f.label, "flag_type": f.flag_type,
            "content": f.content, "weight": f.weight,
        }
        for f in flags
    ])


@admin_bp.route("/challenges/<int:challenge_id>/flags", methods=["POST"])
@admins_only
def create_flag(challenge_id: int):
    if EdoChallenge.query.get(challenge_id) is None:
        return jsonify(success=False, error="challenge_not_found"), 404
    data = request.get_json() or {}
    weight = int(data.get("weight", 0))
    if not (0 <= weight <= 100):
        return jsonify(success=False, error="weight must be 0-100"), 400
    flag = EdoFlag(
        challenge_id=challenge_id,
        flag_type=data.get("flag_type", "static"),
        content=data.get("content", ""),
        weight=weight,
        label=data.get("label"),
    )
    db.session.add(flag)
    db.session.commit()
    if not _flag_weights_sum_to_100(challenge_id):
        # Warn but don't block — admins may still be editing.
        return jsonify(success=True, id=flag.id, warning="weights do not sum to 100")
    return jsonify(success=True, id=flag.id)


@admin_bp.route("/flags/<int:flag_id>", methods=["PATCH"])
@admins_only
def update_flag(flag_id: int):
    flag = EdoFlag.query.get(flag_id)
    if flag is None:
        return jsonify(success=False, error="not_found"), 404
    data = request.get_json() or {}
    for k in ("label", "content", "flag_type"):
        if k in data:
            setattr(flag, k, data[k])
    if "weight" in data:
        w = int(data["weight"])
        if not (0 <= w <= 100):
            return jsonify(success=False, error="weight must be 0-100"), 400
        flag.weight = w
    db.session.commit()
    return jsonify(success=True)


@admin_bp.route("/flags/<int:flag_id>", methods=["DELETE"])
@admins_only
def delete_flag(flag_id: int):
    flag = EdoFlag.query.get(flag_id)
    if flag is None:
        return jsonify(success=False, error="not_found"), 404
    db.session.delete(flag)
    db.session.commit()
    return jsonify(success=True)


def _flag_weights_sum_to_100(challenge_id: int) -> bool:
    total = db.session.query(db.func.coalesce(db.func.sum(EdoFlag.weight), 0)) \
        .filter(EdoFlag.challenge_id == challenge_id).scalar()
    return int(total) == 100


# ---------- Containers ----------

@admin_bp.route("/instances", methods=["GET"])
@admins_only
def list_instances():
    instances = EdoInstance.query.order_by(EdoInstance.created_at.desc()).limit(500).all()
    return jsonify(success=True, instances=[_serialize_instance(i) for i in instances])


@admin_bp.route("/instances/<int:instance_id>/teardown", methods=["POST"])
@admins_only
def force_teardown(instance_id: int):
    inst = EdoInstance.query.get(instance_id)
    if inst is None:
        return jsonify(success=False, error="not_found"), 404
    try:
        if inst.container_id:
            _client().container_teardown(inst.container_id)
        inst.status = "stopped"
        _audit("admin", "force_teardown", inst)
        db.session.commit()
        return jsonify(success=True)
    except DaemonError as e:
        return jsonify(success=False, error=str(e)), 502


# ---------- WireGuard ----------

@admin_bp.route("/wg/bulk_generate", methods=["POST"])
@admins_only
def wg_bulk_generate():
    """
    Generate a WG peer for every user (or every team, if team_mode) that
    doesn't already have one. Long-running — returns a summary.
    """
    data = request.get_json() or {}
    scope = data.get("scope", "users")  # "users" | "teams"
    client = _client()
    created, skipped, failed = 0, 0, 0

    if scope == "teams":
        # One peer per team captain (simplest attribution).
        teams = Teams.query.all()
        for t in teams:
            if not t.captain_id:
                skipped += 1
                continue
            if EdoVPNPeer.query.filter_by(user_id=t.captain_id, revoked=False).first():
                skipped += 1
                continue
            try:
                peer = client.wg_generate_peer(user_id=t.captain_id, team_id=t.id)
                _persist_peer(peer, user_id=t.captain_id, team_id=t.id)
                created += 1
            except DaemonError as e:
                logger.warning("bulk wg for team %s failed: %s", t.id, e)
                failed += 1
    else:
        users = Users.query.filter_by(banned=False, hidden=False).all()
        for u in users:
            if EdoVPNPeer.query.filter_by(user_id=u.id, revoked=False).first():
                skipped += 1
                continue
            try:
                peer = client.wg_generate_peer(user_id=u.id, team_id=u.team_id)
                _persist_peer(peer, user_id=u.id, team_id=u.team_id)
                created += 1
            except DaemonError as e:
                logger.warning("bulk wg for user %s failed: %s", u.id, e)
                failed += 1

    db.session.commit()
    return jsonify(success=True, created=created, skipped=skipped, failed=failed)


@admin_bp.route("/wg/peers/<int:user_id>", methods=["DELETE"])
@admins_only
def wg_revoke_peer(user_id: int):
    peer = EdoVPNPeer.query.filter_by(user_id=user_id, revoked=False).first()
    if peer is None:
        return jsonify(success=False, error="not_found"), 404
    try:
        _client().wg_revoke_peer(peer.public_key)
        peer.revoked = True
        db.session.commit()
        return jsonify(success=True)
    except DaemonError as e:
        return jsonify(success=False, error=str(e)), 502


# ---------- Audit log ----------

@admin_bp.route("/audit", methods=["GET"])
@admins_only
def audit_log():
    limit = min(int(request.args.get("limit", 100)), 1000)
    rows = EdoAuditLog.query.order_by(EdoAuditLog.ts.desc()).limit(limit).all()
    return jsonify(success=True, events=[
        {
            "id": r.id, "ts": r.ts.isoformat(),
            "actor": r.actor, "event": r.event,
            "challenge_id": r.challenge_id, "instance_id": r.instance_id,
            "details": r.details,
        }
        for r in rows
    ])


# ---------- Health ----------

@admin_bp.route("/health", methods=["GET"])
@admins_only
def health():
    try:
        _client().ping()
        return jsonify(success=True, daemon="ok")
    except DaemonError as e:
        return jsonify(success=False, daemon="down", error=str(e)), 502


# ---------- helpers ----------

def _persist_peer(peer: dict, user_id: int, team_id: int | None):
    row = EdoVPNPeer(
        user_id=user_id,
        team_id=team_id,
        public_key=peer["public_key"],
        private_key=peer["private_key"],
        assigned_ip=peer["assigned_ip"],
    )
    db.session.add(row)


def _serialize_instance(i: EdoInstance) -> dict:
    return {
        "id": i.id, "challenge_id": i.challenge_id,
        "team_id": i.team_id, "user_id": i.user_id,
        "container_id": i.container_id, "container_name": i.container_name,
        "host_ip": i.host_ip, "host_ports": i.host_ports,
        "status": i.status,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "expires_at": i.expires_at.isoformat() if i.expires_at else None,
        "error_message": i.error_message,
    }


def _audit(actor: str, event: str, inst: EdoInstance | None, details: dict | None = None):
    db.session.add(EdoAuditLog(
        actor=actor,
        event=event,
        challenge_id=inst.challenge_id if inst else None,
        instance_id=inst.id if inst else None,
        details=json.dumps(details) if details else None,
    ))
