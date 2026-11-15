"""Structural checks for the India compliance catalog (references, statuses, rule files)."""
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CATALOG = json.load(open(os.path.join(ROOT, "compliance", "india_catalog.json"), encoding="utf-8"))
CHECKS = {c["id"]: c for c in CATALOG["checks"]}


def test_ids_are_unique():
    assert len(CHECKS) == len(CATALOG["checks"])
    ids = [o["id"] for o in CATALOG["obligations"]]
    assert len(ids) == len(set(ids))


def test_obligations_reference_existing_checks():
    for ob in CATALOG["obligations"]:
        for check_id in ob["checks"]:
            assert check_id in CHECKS, f"{ob['id']} references unknown check {check_id}"


def test_status_and_verification_values_are_valid():
    for c in CATALOG["checks"]:
        assert c["status"] in CATALOG["legend"]["check_status"]
    for ob in CATALOG["obligations"]:
        assert ob["in_force"] in CATALOG["legend"]["in_force"]
        assert ob["verification"] in CATALOG["legend"]["verification"]
        assert ob["coverage"] in ("partial", "manual-only", "full")


def test_manual_only_obligations_have_no_checks():
    for ob in CATALOG["obligations"]:
        assert (ob["coverage"] == "manual-only") == (not ob["checks"])


def test_implemented_checks_match_rule_ids_in_framework_mapping():
    # framework_mapping.py is the source of truth for rule ids used by the rule engine.
    from lambdas.rule_engine.framework_mapping import PRIVACY_CLAUSE_MAP
    for c in CATALOG["checks"]:
        if c["status"] == "implemented":
            assert c["rule"] in PRIVACY_CLAUSE_MAP, f"rule {c['rule']} is not a known rule id"
        else:
            assert c["rule"] is None


def test_only_primary_verified_entries_claim_primary():
    # Guard against over-claiming: nothing in the draft has been checked against official text yet.
    assert all(ob["verification"] != "primary" for ob in CATALOG["obligations"])
