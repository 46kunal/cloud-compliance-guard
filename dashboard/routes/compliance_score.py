from collections import Counter

from flask import Blueprint, jsonify

from db.schema import connect, get_resources_scanned, get_violations

compliance_score_bp = Blueprint("compliance_score", __name__)

# ponytail: flat penalty per violation; switch to per-resource pass rate if rules get weighted per framework
SEVERITY_PENALTY = {"HIGH": 15, "MEDIUM": 8, "LOW": 3}


def compute_score(violations: list) -> int:
    penalty = sum(SEVERITY_PENALTY.get(v.get("severity"), 3) for v in violations)
    return max(0, 100 - penalty)


@compliance_score_bp.route("/api/compliance-score")
def compliance_score():
    conn = connect()
    try:
        violations = get_violations(conn)
        resources_scanned = get_resources_scanned(conn)
    finally:
        conn.close()

    return jsonify({
        "score": compute_score(violations),
        "resources_scanned": resources_scanned,
        "total_violations": len(violations),
        "by_severity": dict(Counter(v["severity"] for v in violations)),
        "by_rule": dict(Counter(v["rule"] for v in violations)),
    })
