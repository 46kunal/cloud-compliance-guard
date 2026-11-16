from flask import Blueprint, jsonify
import re

from compliance.catalog import obligations_for_rule
from dashboard.account import in_scope, visible_scope
from db.store import connect, get_finding, get_finding_evidence, get_findings, get_violations

violations_bp = Blueprint("violations", __name__)


@violations_bp.route("/api/violations")
def list_violations():
    conn = connect()
    try:
        return jsonify(in_scope(get_violations(conn), visible_scope(conn)))
    finally:
        conn.close()


@violations_bp.route("/api/findings")
def list_findings():
    conn = connect()
    try:
        findings = in_scope(get_findings(conn), visible_scope(conn))
        for finding in findings:
            finding["obligations"] = obligations_for_rule(finding["rule"])
        return jsonify(findings)
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
        finding = get_finding(conn, int(finding_id))
        if finding is None:
            return jsonify({"error": "Finding not found", "evidence": []}), 404
        evidence = get_finding_evidence(conn, finding["id"])
        return jsonify({"finding_id": finding["id"], "evidence": evidence})
    finally:
        conn.close()
