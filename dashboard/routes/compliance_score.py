from collections import Counter

from flask import Blueprint, jsonify

from db.schema import connect, get_resources_scanned, get_violations

compliance_score_bp = Blueprint("compliance_score", __name__)

def compute_score(violations: list, resources_scanned: int) -> int:
    """Percent of scanned resources with zero violations."""
    if resources_scanned <= 0:
        return 100
    violating = len({v["resource_id"] for v in violations})
    return round(100 * max(0, resources_scanned - violating) / resources_scanned)


@compliance_score_bp.route("/api/compliance-score")
def compliance_score():
    conn = connect()
    try:
        violations = get_violations(conn)
        resources_scanned = get_resources_scanned(conn)
    finally:
        conn.close()

    return jsonify({
        "score": compute_score(violations, resources_scanned),
        "resources_scanned": resources_scanned,
        "total_violations": len(violations),
        "by_severity": dict(Counter(v["severity"] for v in violations)),
        "by_rule": dict(Counter(v["rule"] for v in violations)),
    })
