from flask import Blueprint, jsonify

from db.schema import connect, get_violations

violations_bp = Blueprint("violations", __name__)


@violations_bp.route("/api/violations")
def list_violations():
    conn = connect()
    try:
        return jsonify(get_violations(conn))
    finally:
        conn.close()
