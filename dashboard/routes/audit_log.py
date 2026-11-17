import os

from flask import Blueprint, jsonify

from db.store import connect, get_audit_log
from lambdas.audit_logger.hash_chain import verify_chain

audit_log_bp = Blueprint("audit_log", __name__)


@audit_log_bp.route("/api/audit-anchors")
def audit_anchors():
    """Signed, locked receipts of the chain head, checked against the live chain."""
    from lambdas.audit_logger import anchor_store
    if not anchor_store.configured():
        return jsonify({"configured": False})
    conn = connect()
    try:
        entries = get_audit_log(conn)
    finally:
        conn.close()
    try:
        report = anchor_store.verify(entries, anchor_store.list_anchors())
    except Exception as error:
        return jsonify({"configured": True, "error": f"Could not read the anchors: {error}"}), 502
    return jsonify({"configured": True, "lock_mode": os.environ.get("ANCHOR_LOCK_MODE", "GOVERNANCE").upper(),
                    "retention_days": int(os.environ.get("ANCHOR_RETENTION_DAYS", "30")), **report})


@audit_log_bp.route("/api/audit-log")
def audit_log():
    conn = connect()
    try:
        entries = get_audit_log(conn)
    finally:
        conn.close()
    return jsonify({"chain_valid": verify_chain(entries), "entries": entries})
