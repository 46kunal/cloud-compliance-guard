"""Live AWS scanner with explicit collection coverage and persistent finding lifecycle."""
import os
import sys
import threading
import time
from datetime import datetime, timezone

import boto3

from db.store import begin_scan, connect, count_finding_events, get_audit_log, get_violations, save_scan
from dashboard.evidence import build_evidence_records
from lambdas.audit_logger.hash_chain import GENESIS, append_entry
from lambdas.remediation.handler import remediate_violations
from lambdas.risk_classifier.handler import classify_violations
from lambdas.rule_engine.handler import get_all_resources, run_rule_engine

_scan_lock = threading.Lock()
SERVICES = ("s3", "iam", "ec2", "cloudtrail")


def _key(v: dict) -> tuple:
    return v.get("rule"), v.get("resource_id")


def _account_scope():
    configured = os.environ.get("POLICYGUARD_ACCOUNT_ID") or os.environ.get("POLICYGUARD_ACCOUNT_SCOPE")
    if configured:
        return configured
    try:
        return boto3.client("sts").get_caller_identity()["Account"]
    except Exception:
        # Keep scan records distinct from the legacy seed/test scope even when identity lookup fails.
        return "unknown-configured-aws-account"


def _region_scope():
    region = boto3.session.Session().region_name
    return region or "us-east-1 (collector fallback)"


def _scan_status(service_statuses, engine_ok=True):
    values = [service_statuses.get(name, {}).get("status", "NOT_SCANNED") for name in SERVICES]
    successful = values.count("SUCCESS")
    if not engine_ok or successful == 0:
        return "FAILED"
    if all(value == "SUCCESS" for value in values):
        return "COMPLETED"
    return "PARTIAL"


def scan_and_save(conn, resources: list = None, collection_report: dict = None) -> dict:
    with _scan_lock:
        started_at = datetime.now(timezone.utc).isoformat()
        account_scope, region_scope = _account_scope(), _region_scope()
        scan_id = begin_scan(conn, started_at, account_scope, region_scope)
        report = collection_report if collection_report is not None else {name: {"status": "NOT_SCANNED", "errors": []} for name in SERVICES}
        engine_ok = True
        assessment_errors = []
        try:
            if resources is None:
                resources = get_all_resources(report)
            elif collection_report is None:
                # Explicit resource injection is for tests/callers; it represents a completed supplied scope.
                for name in SERVICES:
                    report[name] = {"status": "SUCCESS", "errors": []}
            raw_violations = run_rule_engine(resources)
            classified = classify_violations(raw_violations)
        except Exception as e:
            engine_ok = False
            classified = []
            resources = resources or []
            assessment_errors.append(str(e))
            print(f"[SCAN] assessment failed: {e}", file=sys.stderr)

        status = _scan_status(report, engine_ok)
        successful_services = {name for name in SERVICES if engine_ok and report[name]["status"] == "SUCCESS"}
        resource_service = {
            "object_storage": "s3", "iam_policy": "iam", "iam_user": "iam",
            "security_group": "ec2", "cloudtrail_config": "cloudtrail",
        }
        assessed_resources = [r for r in resources if resource_service.get(r.get("resource_type")) in successful_services]
        previous = get_violations(conn)
        prev_keys = {_key(v) for v in previous}
        cur_keys = {_key(v) for v in classified}
        new = [v for v in classified if _key(v) not in prev_keys]

        # Preserve existing behaviour: only newly observed violations are passed to the existing
        # dry-run/allowlist remediation layer. Its safety gates and actions are unchanged.
        new_results = remediate_violations(new) if status != "FAILED" else []
        kept_results = [v["remediation"] for v in previous if _key(v) in cur_keys and v["remediation"]]
        guidance_by_key = {(item.get("rule"), item.get("resource_id")): item
                           for item in new_results + kept_results if isinstance(item, dict)}
        for finding in classified:
            finding["remediation"] = guidance_by_key.get(_key(finding))
        evidence_records = build_evidence_records(
            classified, resources, scan_id, datetime.now(timezone.utc).isoformat(), account_scope, region_scope,
            collection_report=report,
        )
        events = [("VIOLATION_DETECTED", v) for v in new]
        events += [("REMEDIATION", r) for r in new_results]
        source_service = {"public_storage": "s3", "encryption_at_rest": "s3", "wildcard_permission": "iam",
                          "mfa_required": "iam", "open_admin_ports": "ec2", "cloudtrail_enabled": "cloudtrail"}
        if status != "FAILED":
            for finding in previous:
                service = source_service.get(finding.get("rule"))
                if _key(finding) not in cur_keys and service in successful_services:
                    events.append(("VIOLATION_RESOLVED", {k: finding.get(k) for k in ("rule", "resource_id", "clause", "severity")}))

        chain = get_audit_log(conn)
        previous_hash = chain[-1]["entry_hash"] if chain else GENESIS
        entries = []
        for event_type, details in events:
            entry = append_entry(event_type, details, previous_hash)
            entries.append(entry)
            previous_hash = entry["entry_hash"]

        errors = [{"service": name, "message": error}
                  for name, detail in report.items() for error in detail.get("errors", [])]
        errors.extend({"service": "assessment", "message": error} for error in assessment_errors)
        allow_resolve = status != "FAILED" and engine_ok
        save_scan(
            conn, len(resources), classified, new_results + kept_results, entries,
            scan_id=scan_id, started_at=started_at, status=status, account_scope=account_scope,
            region_scope=region_scope, resources_assessed=len(assessed_resources),
            services_scanned=[name for name in SERVICES if report[name]["status"] != "NOT_SCANNED"],
            service_statuses=report, collection_errors=errors, allow_resolve=allow_resolve,
            assessed_resource_records=assessed_resources,
            evidence_records=evidence_records,
        )
        resolved = count_finding_events(conn, scan_id, 'RESOLVED')
        return {
            "scan_id": scan_id, "status": status, "resources": len(resources),
            "resources_discovered": len(resources), "resources_assessed": len(assessed_resources),
            "violations": len(classified), "new": len(new), "resolved": resolved,
            "services_scanned": [name for name in SERVICES if report[name]["status"] != "NOT_SCANNED"],
            "service_statuses": report, "collection_errors": errors,
            "account_scope": account_scope, "region_scope": region_scope,
        }


def start_background_scanner(interval_seconds: int) -> threading.Thread:
    def loop():
        while True:
            conn = connect()
            try:
                result = scan_and_save(conn)
                print(f"[SCAN] {result}")
            except Exception as e:
                print(f"[SCAN] failed: {e}", file=sys.stderr)
            finally:
                conn.close()
            time.sleep(interval_seconds)

    thread = threading.Thread(target=loop, daemon=True, name="policyguard-scanner")
    thread.start()
    return thread
