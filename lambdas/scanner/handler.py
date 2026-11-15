"""Scheduled scanner (EventBridge -> Lambda).

Runs one full scan with the same code the dashboard uses, stores results in DynamoDB, publishes
CloudWatch metrics through Embedded Metric Format log lines (no extra API calls), and emails an SNS
alert when a scan finds new HIGH-severity findings.

Environment:
    POLICYGUARD_BACKEND=dynamodb   POLICYGUARD_PROFILE=india   POLICYGUARD_TABLE_PREFIX=...
    POLICYGUARD_ALERT_TOPIC_ARN    optional SNS topic for HIGH-finding alerts
"""
import json
import os
import time

# Remediation stays in dry-run unless an operator deliberately changes this and the allowlist.
os.environ.setdefault("POLICYGUARD_DRY_RUN", "true")
os.environ.setdefault("POLICYGUARD_BACKEND", "dynamodb")


def _emit_metrics(result: dict, high_open: int, duration: float) -> None:
    """One EMF line; CloudWatch turns it into metrics when the log group is processed."""
    print(json.dumps({
        "_aws": {"Timestamp": int(time.time() * 1000), "CloudWatchMetrics": [{
            "Namespace": "PolicyGuard", "Dimensions": [["Service"]],
            "Metrics": [{"Name": "OpenFindings", "Unit": "Count"}, {"Name": "HighFindings", "Unit": "Count"},
                        {"Name": "ResourcesAssessed", "Unit": "Count"}, {"Name": "ScanSeconds", "Unit": "Seconds"},
                        {"Name": "ScanFailed", "Unit": "Count"}]}]},
        "Service": "scanner", "OpenFindings": result.get("violations", 0), "HighFindings": high_open,
        "ResourcesAssessed": result.get("resources_assessed", 0), "ScanSeconds": round(duration, 2),
        "ScanFailed": 1 if result.get("status") == "FAILED" else 0}))


def _alert(result: dict, new_high: list) -> None:
    topic = os.environ.get("POLICYGUARD_ALERT_TOPIC_ARN")
    if not topic or not new_high:
        return
    import boto3
    lines = [f"- {f['rule']} on {f['resource_id']}" for f in new_high[:20]]
    boto3.client("sns").publish(
        TopicArn=topic, Subject=f"PolicyGuard: {len(new_high)} new HIGH finding(s)",
        Message="New HIGH-severity findings in scan %s (%s):\n%s\n\nThis is a configuration finding, not a legal determination."
                % (result.get("scan_id"), result.get("account_scope"), "\n".join(lines)))


def lambda_handler(event, context):
    from dashboard.scanner import scan_and_save
    from db.store import connect, get_findings

    started = time.time()
    conn = connect()
    try:
        before = {f["id"] for f in get_findings(conn)}
        result = scan_and_save(conn)
        findings = get_findings(conn, include_resolved=False)
    finally:
        conn.close()
    high = [f for f in findings if f.get("severity") == "HIGH"]
    new_high = [f for f in high if f["id"] not in before]
    _emit_metrics(result, len(high), time.time() - started)
    _alert(result, new_high)
    return result
