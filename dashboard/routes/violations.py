from flask import Blueprint, jsonify
import re

from db.schema import connect, get_finding_evidence, get_findings, get_violations

violations_bp = Blueprint("violations", __name__)


@violations_bp.route("/api/violations")
def list_violations():
    conn = connect()
    try:
        return jsonify(get_violations(conn))
    finally:
        conn.close()


@violations_bp.route("/api/findings")
def list_findings():
    conn = connect()
    try:
        return jsonify(get_findings(conn))
    finally:
        conn.close()


@violations_bp.route("/api/findings/<finding_id>/evidence")
def finding_evidence(finding_id):
    if not re.fullmatch(r"[1-9][0-9]*", finding_id):
        return jsonify({"error": "finding_id must be a positive integer", "evidence": []}), 400
    if len(finding_id) > 19 or int(finding_id) > 9223372036854775807:
        return jsonify({"error": "finding_id is outside the supported range", "evidence": []}), 400
    conn = connect()
    try:
        finding = conn.execute("SELECT id FROM findings WHERE id=?", (int(finding_id),)).fetchone()
        if finding is None:
            return jsonify({"error": "Finding not found", "evidence": []}), 404
        evidence = get_finding_evidence(conn, finding["id"])
        return jsonify({"finding_id": finding["id"], "evidence": evidence})
    finally:
        conn.close()
