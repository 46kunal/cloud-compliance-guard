from flask import Blueprint, jsonify

from db.schema import connect, get_audit_log
from lambdas.audit_logger.hash_chain import verify_chain

audit_log_bp = Blueprint("audit_log", __name__)


@audit_log_bp.route("/api/audit-log")
def audit_log():
    conn = connect()
    try:
        entries = get_audit_log(conn)
    finally:
        conn.close()
    return jsonify({"chain_valid": verify_chain(entries), "entries": entries})
