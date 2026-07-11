"""
Admin-only routes.

CTFd's `admins_only` decorator gates access; every response is JSON except
for the template-rendering routes at the top which serve HTML for the plugin
config page.
"""
from __future__ import annotations

import json
import logging

from flask import Blueprint, jsonify, render_template, request
from CTFd.models import Flags, Users, db
from CTFd.utils.decorators import admins_only

from ..config import EdoConfig
from ..daemon_client import DaemonError, EdoDaemonClient
from ..models import EdoAuditLog, EdoFlagWeight, EdoInstance, EdoPeer, EdoSettings
from ..owner import owner_display_name, resolve_owner_for_user

logger = logging.getLogger("edo.api.admin")

admin_bp = Blueprint("edo_admin", __name__, template_folder="../templates")


def _client() -> EdoDaemonClient:
    return EdoDaemonClient(
        socket_path=EdoConfig.DAEMON_SOCKET_PATH,
        timeout=EdoConfig.DAEMON_RPC_TIMEOUT,
    )


# ---------- Config page ----------

@admin_bp.route("/settings", methods=["GET"])
@admins_only
def settings_page():
    diffs = EdoConfig.DIFFICULTIES
    known = {
        "max_containers_per_owner": EdoConfig.DEFAULT_MAX_CONTAINERS_PER_OWNER,
        "container_ttl_seconds":   EdoConfig.DEFAULT_CONTAINER_TTL_SECONDS,
        "extend_seconds":          EdoConfig.DEFAULT_EXTEND_SECONDS,
        "extend_threshold_seconds": EdoConfig.DEFAULT_EXTEND_THRESHOLD_SECONDS,
        "submit_rate_limit":       EdoConfig.DEFAULT_SUBMIT_RATE_LIMIT,
        "submit_rate_window":      EdoConfig.DEFAULT_SUBMIT_RATE_WINDOW,
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
        "max_containers_per_owner", "container_ttl_seconds",
        "extend_seconds", "extend_threshold_seconds",
        "submit_rate_limit", "submit_rate_window",
        "vpn_server_endpoint",
        "reconcile_interval_seconds", "ttl_check_interval_seconds",
    }
    for k, v in payload.items():
        if k in allowed:
            EdoSettings.set(k, v)
    return jsonify(success=True)


# ---------- Flag weights ----------
# Flag content/type/regex live entirely in CTFd's own Flags table and its
# native admin editor (the "Flags" tab in the challenge-edit modal, which
# CTFd renders for every challenge type automatically). These routes ONLY
# manage the percentage-of-value each native flag is worth.

@admin_bp.route("/challenges/<int:challenge_id>/flag_weights", methods=["GET"])
@admins_only
def list_flag_weights(challenge_id: int):
    flags = Flags.query.filter_by(challenge_id=challenge_id).all()
    weights = {
        w.flag_id: w.weight_pct
        for w in EdoFlagWeight.query.filter(
            EdoFlagWeight.flag_id.in_([f.id for f in flags])
        ).all()
    }
    return jsonify(success=True, flags=[
        {
            "id": f.id,
            "type": f.type,
            "content": f.content,
            "weight_pct": weights.get(f.id, 100),
        }
        for f in flags
    ])


@admin_bp.route("/flags/<int:flag_id>/weight", methods=["PATCH"])
@admins_only
def set_flag_weight(flag_id: int):
    if Flags.query.get(flag_id) is None:
        return jsonify(success=False, error="flag_not_found"), 404
    data = request.get_json() or {}
    weight = data.get("weight_pct")
    if weight is None or not (0 <= int(weight) <= 100):
        return jsonify(success=False, error="weight_pct must be 0-100"), 400

    row = EdoFlagWeight.query.filter_by(flag_id=flag_id).first()
    if row is None:
        row = EdoFlagWeight(flag_id=flag_id, weight_pct=int(weight))
        db.session.add(row)
    else:
        row.weight_pct = int(weight)
    db.session.commit()

    challenge_id = Flags.query.get(flag_id).challenge_id
    if not _flag_weights_sum_to_100(challenge_id):
        return jsonify(success=True, warning="weights do not sum to 100")
    return jsonify(success=True)


def _flag_weights_sum_to_100(challenge_id: int) -> bool:
    flag_ids = [f.id for f in Flags.query.filter_by(challenge_id=challenge_id).all()]
    if not flag_ids:
        return True
    total = db.session.query(db.func.coalesce(db.func.sum(EdoFlagWeight.weight_pct), 0)) \
        .filter(EdoFlagWeight.flag_id.in_(flag_ids)).scalar()
    # Flags with no EdoFlagWeight row yet default to 100 in list_flag_weights,
    # but an unset row contributes 0 to this SUM — count them at their
    # effective default so a fresh single-flag challenge reads as valid.
    unset = len(flag_ids) - EdoFlagWeight.query.filter(
        EdoFlagWeight.flag_id.in_(flag_ids)
    ).count()
    return int(total) + 100 * unset == 100


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
            _client().container_release_instance(inst.container_id)
        inst.status = "stopped"
        _audit("admin", "force_teardown", inst)
        db.session.commit()
        return jsonify(success=True)
    except DaemonError as e:
        return jsonify(success=False, error=str(e)), 502


@admin_bp.route("/kill_switch", methods=["POST"])
@admins_only
def kill_switch():
    """Emergency stop: tears down every container the daemon knows about.
    Leaves WireGuard peers intact — this is not a VPN lockout.
    """
    try:
        result = _client().kill_switch()
        EdoInstance.query.filter(
            EdoInstance.status.in_(("pending", "running"))
        ).update({"status": "stopped"}, synchronize_session=False)
        db.session.add(EdoAuditLog(actor="admin", event="kill_switch", details=json.dumps(result)))
        db.session.commit()
        return jsonify(success=True, **result)
    except DaemonError as e:
        return jsonify(success=False, error=str(e)), 502


# ---------- WireGuard ----------

@admin_bp.route("/wg/bulk_generate", methods=["POST"])
@admins_only
def wg_bulk_generate():
    """
    Generate a WG peer for every active user that doesn't already have one.

    VPN identity is always per-user (each teammate keeps their own device),
    even in team mode — only the container-access scope (owner_type/
    owner_id) differs by mode. Long-running; returns a summary.
    """
    client = _client()
    created, skipped, failed = 0, 0, 0

    for u in Users.query.filter_by(banned=False, hidden=False).all():
        if EdoPeer.query.filter_by(user_id=u.id, revoked=False).first():
            skipped += 1
            continue
        owner = resolve_owner_for_user(u)
        if owner is None:
            skipped += 1  # team-mode user with no team yet
            continue
        owner_type, owner_id = owner
        try:
            peer = client.wg_ensure_peer(user_id=u.id, owner_type=owner_type, owner_id=owner_id)
            db.session.add(EdoPeer(
                user_id=u.id, owner_type=owner_type, owner_id=owner_id,
                public_key=peer["public_key"], private_key=peer.get("private_key"),
                assigned_ip=peer["assigned_ip"],
            ))
            created += 1
        except DaemonError as e:
            logger.warning("bulk wg for user %s failed: %s", u.id, e)
            failed += 1

    db.session.commit()
    return jsonify(success=True, created=created, skipped=skipped, failed=failed)


@admin_bp.route("/wg/peers/<int:user_id>", methods=["DELETE"])
@admins_only
def wg_revoke_peer(user_id: int):
    peer = EdoPeer.query.filter_by(user_id=user_id, revoked=False).first()
    if peer is None:
        return jsonify(success=False, error="not_found"), 404
    try:
        _client().wg_remove_peer(user_id)
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

def _serialize_instance(i: EdoInstance) -> dict:
    return {
        "id": i.id, "challenge_id": i.challenge_id,
        "owner_type": i.owner_type, "owner_id": i.owner_id,
        "owner_name": owner_display_name(i.owner_type, i.owner_id),
        "container_id": i.container_id, "container_name": i.container_name,
        "assigned_ip": i.assigned_ip, "host_ports": i.host_ports,
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
