from collections import Counter

from flask import Blueprint, jsonify

from dashboard.account import in_scope, latest_scan_in_scope, visible_scope
from db.store import connect, get_last_scan_time, get_scan_assessed_resource_ids, get_violations

compliance_score_bp = Blueprint("compliance_score", __name__)


def compute_score(violations: list, resources_scanned: int):
    """Share of successfully assessed resources with no open finding; None means not assessed."""
    if resources_scanned <= 0:
        return None
    violating = len({(v.get("provider", "aws"), v.get("account_scope"), v.get("resource_type"), v["resource_id"])
                     for v in violations})
    return round(100 * max(0, resources_scanned - violating) / resources_scanned)


@compliance_score_bp.route("/api/compliance-score")
def compliance_score():
    conn = connect()
    try:
        scope = visible_scope(conn)
        violations = in_scope(get_violations(conn), scope)
        scan = latest_scan_in_scope(conn, scope)
        resources_assessed = int(scan["resources_assessed"] or 0) if scan else 0
        last_scan = get_last_scan_time(conn) if scope is None else (scan or {}).get("completed_at")
        assessed_resources = get_scan_assessed_resource_ids(conn, scan["id"]) if scan else set()
    finally:
        conn.close()

    # Score only the latest assessment scope's successfully assessed resources.
    if scan:
        score_findings = [v for v in violations
                          if v.get("account_scope") in (scan["account_scope"], "legacy")
                          and (v.get("resource_id"), v.get("resource_type")) in assessed_resources]
    else:
        score_findings = []
    score = compute_score(score_findings, resources_assessed)
    discovered = int(scan["resources_discovered"] or 0) if scan else 0
    coverage = round(100 * resources_assessed / discovered) if discovered else None
    severity = Counter(v.get("severity", "UNKNOWN") for v in violations)
    return jsonify({
        "score": score,
        "score_label": "Not Assessed" if score is None else f"{score}%",
        "score_method": "Assessed resources with no open findings / successfully assessed resources",
        "score_limitation": "A configuration finding score is not a legal compliance determination; resources with incomplete collection are excluded.",
        "resources_scanned": resources_assessed,
        "resources_assessed": resources_assessed,
        "resources_discovered": discovered,
        "scan_coverage": coverage,
        "last_scan": last_scan,
        "scan": scan,
        "total_violations": len(violations),
        "score_findings": len(score_findings),
        "by_severity": dict(severity),
        "by_rule": dict(Counter(v["rule"] for v in violations)),
    })
