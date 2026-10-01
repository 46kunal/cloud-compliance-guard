import importlib
import importlib.util
import json
import os
import sys

try:
    from lambdas.remediation.safety.dry_run import DRY_RUN
except ModuleNotFoundError:
    try:
        from safety.dry_run import DRY_RUN
    except ModuleNotFoundError:
        _path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "safety", "dry_run.py")
        _spec = importlib.util.spec_from_file_location("dry_run", _path)
        _mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        DRY_RUN = _mod.DRY_RUN

# rule name -> action module in actions/
RULE_TO_ACTION = {
    "public_storage": "close_public_bucket",
    "encryption_at_rest": "enforce_encryption",
    "wildcard_permission": "revoke_iam_permission",
}

# mfa_required is MEDIUM but has no safe auto-fix (needs a human device), so it is reported only.
REMEDIATE_SEVERITIES = ("HIGH", "MEDIUM")


def _load_action(name: str):
    for import_path in [f"lambdas.remediation.actions.{name}", f"actions.{name}"]:
        try:
            return importlib.import_module(import_path)
        except ModuleNotFoundError:
            continue
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "actions", f"{name}.py")
    spec = importlib.util.spec_from_file_location(name, file_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def remediate_violations(classified: list, dry_run: bool = None) -> list:
    """
    Dispatches each classified violation with a matching action and a
    HIGH/MEDIUM severity. Safety (dry-run + allowlist) is enforced inside each action.
    """
    dry_run = DRY_RUN if dry_run is None else dry_run
    results = []
    for violation in classified:
        if not isinstance(violation, dict):
            continue
        rule = violation.get("rule")
        resource_id = violation.get("resource_id", "")
        action_name = RULE_TO_ACTION.get(rule)

        if action_name is None or violation.get("severity") not in REMEDIATE_SEVERITIES:
            results.append({
                "action": "manual_review",
                "resource_id": resource_id,
                "rule": rule,
                "dry_run": dry_run,
                "success": False,
                "message": "No automated remediation; flagged for manual review",
            })
            continue

        result = _load_action(action_name).remediate(resource_id, dry_run=dry_run)
        result["rule"] = rule
        results.append(result)
    return results


def lambda_handler(event, context):
    if isinstance(event, dict) and "violations" in event:
        violations = event["violations"]
        dry_run = event.get("dry_run")
    elif isinstance(event, list):
        violations, dry_run = event, None
    else:
        violations, dry_run = [], None

    results = remediate_violations(violations, dry_run=dry_run)
    return {"statusCode": 200, "body": json.dumps(results)}


if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from lambdas.rule_engine.handler import get_all_resources, run_rule_engine
    from lambdas.risk_classifier.handler import classify_violations

    classified = classify_violations(run_rule_engine(get_all_resources()))
    results = remediate_violations(classified)
    if not results:
        print("[REMEDIATE] No violations to remediate.")
    for r in results:
        mode = "DRY-RUN" if r.get("dry_run") else "LIVE"
        print(f"[REMEDIATE] {mode} | {r['action']} | {r['resource_id']} | success={r['success']} | {r.get('message', '')}")
