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

# Configuration comes from the Lambda environment (set by CloudFormation): POLICYGUARD_BACKEND=dynamodb and
# POLICYGUARD_DRY_RUN=true. Nothing here changes process-wide settings on import, so tests and other code that
# import this module can never be redirected to a real database by accident.


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


def _anchor(result: dict) -> dict:
    """Write a signed, locked receipt for the audit chain head. A failure here never fails the scan."""
    try:
        from db.store import connect, get_audit_log
        from lambdas.audit_logger import anchor_store
        if not anchor_store.configured():
            return {"anchored": False, "reason": "not configured"}
        conn = connect()
        try:
            entries = get_audit_log(conn)
        finally:
            conn.close()
        return anchor_store.anchor(entries, result.get("scan_id"))
    except Exception as error:
        print(f"[ANCHOR] failed: {error}")
        return {"anchored": False, "reason": str(error)[:200]}


def _scan_one(conn, account=None):
    """One scan of the home account (account=None) or one member account through its cross-account role."""
    from contextlib import nullcontext
    from dashboard import monitored
    from dashboard.scanner import scan_and_save
    from db.store import get_findings

    before = {f["id"] for f in get_findings(conn)}
    context = monitored.assumed_session(account) if account else nullcontext()
    with context:
        result = scan_and_save(conn)
    findings = [f for f in get_findings(conn, include_resolved=False) if f.get("account_scope") == result.get("account_scope")]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    new_high = [f for f in high if f["id"] not in before]
    return result, high, new_high


def lambda_handler(event, context):
    """Scans the home account, then every verified and enabled member account.

    event {"account_id": "123456789012"} scans only that member account; {"account_id": "home"} only the home account.
    The returned summary is the home account's result (unchanged shape) plus an "accounts" list."""
    from dashboard import monitored
    from db.store import connect

    wanted = (event or {}).get("account_id") if isinstance(event, dict) else None
    started = time.time()
    conn = connect()
    try:
        home_result = None
        if wanted in (None, "", "home"):
            home_result, high, new_high = _scan_one(conn)
            _emit_metrics(home_result, len(high), time.time() - started)
            _alert(home_result, new_high)
            home_result["anchor"] = _anchor(home_result)
        member_results = []
        for account in monitored.list_accounts(conn):
            if not account.get("enabled") or account.get("status") != "ACTIVE":
                continue
            if wanted not in (None, "", "home", account["account_id"]):
                continue
            try:
                result, _high, new_high = _scan_one(conn, account)
                _alert(result, new_high)
                monitored.record_scan(conn, account["account_id"], result.get("status"))
                member_results.append({"account_id": account["account_id"], "name": account["name"],
                                       "status": result.get("status"), "violations": result.get("violations"),
                                       "resources_assessed": result.get("resources_assessed")})
            except Exception as error:   # one bad account must not stop the others
                print(f"[SCAN] account {account['account_id']} failed: {error}")
                monitored.record_scan(conn, account["account_id"], "FAILED", str(error)[:200])
                member_results.append({"account_id": account["account_id"], "name": account["name"],
                                       "status": "FAILED", "error": str(error)[:200]})
        if member_results and home_result is None:
            home_result = {"status": "SKIPPED", "note": "Only member accounts were scanned."}
        if member_results:
            home_result["anchor"] = home_result.get("anchor") or _anchor(home_result)
        home_result = home_result or {"status": "SKIPPED", "note": "No matching account."}
        home_result["accounts"] = member_results
        return home_result
    finally:
        conn.close()
