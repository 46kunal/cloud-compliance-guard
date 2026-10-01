import json
import os
import sys

try:
    from lambdas.risk_classifier.severity_rules import classify
except ModuleNotFoundError:
    try:
        from severity_rules import classify
    except ModuleNotFoundError:
        import importlib.util
        file_path = os.path.join(os.path.dirname(__file__), "severity_rules.py")
        spec = importlib.util.spec_from_file_location("severity_rules", file_path)
        sev_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sev_mod)
        classify = sev_mod.classify


def classify_violations(violations: list) -> list:
    """
    Adds a 'severity' field to each violation dictionary using severity_rules.classify().
    """
    classified = []
    for violation in violations:
        if isinstance(violation, dict):
            item = dict(violation)
            item["severity"] = classify(item)
            classified.append(item)
    return classified


def lambda_handler(event, context):
    """
    Lambda entry point for risk classification.
    Returns classified violations as JSON.
    """
    if isinstance(event, dict) and "violations" in event:
        violations = event["violations"]
    elif isinstance(event, list):
        violations = event
    else:
        violations = []

    classified = classify_violations(violations)
    return {
        "statusCode": 200,
        "body": json.dumps(classified),
    }


if __name__ == "__main__":
    # Import and run rule_engine's handler
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from lambdas.rule_engine.handler import (
        get_all_resources,
        run_rule_engine,
    )

    resources = get_all_resources()
    violations = run_rule_engine(resources)
    classified_results = classify_violations(violations)

    if classified_results:
        for item in classified_results:
            severity = item.get("severity", "UNKNOWN")
            clause = item.get("clause", "N/A")
            resource_id = item.get("resource_id", "N/A")
            rule = item.get("rule", "N/A")
            print(
                f"[CLASSIFY] Severity: {severity} | Clause: {clause} | Rule: {rule} | Resource: {resource_id}"
            )
    else:
        print("[CLASSIFY] No violations found to classify.")
