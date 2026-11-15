"""Load the India compliance catalog and answer questions the dashboard asks of it."""
import json
import os
from functools import lru_cache

CATALOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "india_catalog.json")


@lru_cache(maxsize=1)
def load_catalog() -> dict:
    with open(CATALOG_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _rule_for_check(check: dict):
    return check.get("rule")


def obligations_for_rule(rule: str) -> list:
    """Obligations whose supporting checks include this rule, as small display records."""
    catalog = load_catalog()
    check_ids = {c["id"] for c in catalog["checks"] if _rule_for_check(c) == rule}
    result = []
    for ob in catalog["obligations"]:
        if check_ids & set(ob["checks"]):
            result.append({"id": ob["id"], "framework": ob["framework"], "citation": ob["citation"],
                           "in_force": ob["in_force"], "verification": ob["verification"]})
    return result


def framework_summary(open_findings: list) -> list:
    """Per-obligation status for the Frameworks page.

    An obligation with automated checks is 'at risk' if any of its rules has an open finding,
    'no open findings' otherwise. Obligations with no implemented check are 'not assessed'.
    """
    catalog = load_catalog()
    checks = {c["id"]: c for c in catalog["checks"]}
    open_by_rule = {}
    for finding in open_findings:
        open_by_rule.setdefault(finding.get("rule"), []).append(finding)

    summary = []
    for ob in catalog["obligations"]:
        implemented = [checks[c] for c in ob["checks"] if checks[c]["status"] == "implemented"]
        pending = [checks[c] for c in ob["checks"] if checks[c]["status"] != "implemented"]
        rules = [c["rule"] for c in implemented]
        findings = [f for rule in rules for f in open_by_rule.get(rule, [])]
        if not implemented:
            state = "not_assessed"
        elif findings:
            state = "findings_open"
        else:
            state = "no_open_findings"
        summary.append({
            "id": ob["id"], "framework": ob["framework"], "citation": ob["citation"], "title": ob["title"],
            "in_force": ob["in_force"], "verification": ob["verification"], "coverage": ob["coverage"],
            "state": state, "open_findings": len(findings),
            "automated_checks": [c["title"] for c in implemented],
            "not_yet_automated": [c["title"] for c in pending],
            "notes": ob.get("notes"),
        })
    return summary
