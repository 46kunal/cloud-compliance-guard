import importlib
import importlib.util
import json
import os
import sys

try:
    from lambdas.audit_logger.hash_chain import append_entry, verify_chain, GENESIS
except ModuleNotFoundError:
    try:
        from hash_chain import append_entry, verify_chain, GENESIS
    except ModuleNotFoundError:
        _path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hash_chain.py")
        _spec = importlib.util.spec_from_file_location("hash_chain", _path)
        _mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        append_entry, verify_chain, GENESIS = _mod.append_entry, _mod.verify_chain, _mod.GENESIS


def build_audit_log(classified: list, remediation_results: list = None, chain: list = None) -> list:
    """
    Appends one entry per detection (with severity) and one per remediation result
    onto chain. Returns a new list; the input chain is not mutated.
    """
    entries = list(chain or [])
    previous = entries[-1]["entry_hash"] if entries else GENESIS

    events = [("VIOLATION_DETECTED", v) for v in classified or []]
    events += [("REMEDIATION", r) for r in remediation_results or []]

    for event_type, details in events:
        entry = append_entry(event_type, details, previous)
        entries.append(entry)
        previous = entry["entry_hash"]
    return entries


def persist_to_dynamodb(entries: list) -> int:
    """Writes entries to DynamoDB if AUDIT_TABLE env var is set. Returns count written."""
    table_name = os.environ.get("AUDIT_TABLE")
    if not table_name:
        return 0
    import boto3
    table = boto3.resource("dynamodb").Table(table_name)
    with table.batch_writer() as batch:
        for e in entries:
            # details stored as a JSON string to avoid DynamoDB float/empty-value limits
            batch.put_item(Item={**e, "details": json.dumps(e["details"], sort_keys=True)})
    return len(entries)


def lambda_handler(event, context):
    event = event if isinstance(event, dict) else {}
    entries = build_audit_log(
        event.get("violations", []),
        event.get("remediation_results", []),
        event.get("chain", []),
    )
    try:
        written = persist_to_dynamodb(entries)
    except Exception as e:
        print(f"[AUDIT] DynamoDB write failed: {e}")
        written = 0
    return {
        "statusCode": 200,
        "body": json.dumps({"entries": entries, "chain_valid": verify_chain(entries), "persisted": written}),
    }


if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from lambdas.rule_engine.handler import get_all_resources, run_rule_engine
    from lambdas.risk_classifier.handler import classify_violations
    from lambdas.remediation.handler import remediate_violations

    classified = classify_violations(run_rule_engine(get_all_resources()))
    entries = build_audit_log(classified, remediate_violations(classified))
    for e in entries:
        print(f"[AUDIT] {e['event_type']} | {e['entry_hash'][:16]}... <- {e['previous_hash'][:16]}")
    print(f"[AUDIT] {len(entries)} entries, chain valid: {verify_chain(entries)}")
