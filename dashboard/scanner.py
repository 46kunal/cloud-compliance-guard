"""
Live scanner for the dashboard: re-scans the AWS account and records only CHANGES in the
audit chain (new violation -> VIOLATION_DETECTED + REMEDIATION, fixed one -> VIOLATION_RESOLVED).
"""
import sys
import threading
import time

from db.schema import connect, get_audit_log, get_violations, save_scan
from lambdas.audit_logger.hash_chain import GENESIS, append_entry
from lambdas.remediation.handler import remediate_violations
from lambdas.risk_classifier.handler import classify_violations
from lambdas.rule_engine.handler import get_all_resources, run_rule_engine

_scan_lock = threading.Lock()


def _key(v: dict) -> tuple:
    return v.get("rule"), v.get("resource_id")


def scan_and_save(conn, resources: list = None) -> dict:
    with _scan_lock:
        resources = get_all_resources() if resources is None else resources
        classified = classify_violations(run_rule_engine(resources))
        previous = get_violations(conn)

        prev_keys = {_key(v) for v in previous}
        cur_keys = {_key(v) for v in classified}
        new = [v for v in classified if _key(v) not in prev_keys]
        resolved = [v for v in previous if _key(v) not in cur_keys]

        # Only newly seen violations are (dry-run / allowlisted) remediated; existing ones keep their result
        new_results = remediate_violations(new)
        kept_results = [v["remediation"] for v in previous if _key(v) in cur_keys and v["remediation"]]

        events = [("VIOLATION_DETECTED", v) for v in new]
        events += [("REMEDIATION", r) for r in new_results]
        events += [("VIOLATION_RESOLVED", {k: v[k] for k in ("rule", "resource_id", "clause", "severity")})
                   for v in resolved]

        chain = get_audit_log(conn)
        previous_hash = chain[-1]["entry_hash"] if chain else GENESIS
        entries = []
        for event_type, details in events:
            entry = append_entry(event_type, details, previous_hash)
            entries.append(entry)
            previous_hash = entry["entry_hash"]

        save_scan(conn, len(resources), classified, new_results + kept_results, entries)
        return {"resources": len(resources), "violations": len(classified),
                "new": len(new), "resolved": len(resolved)}


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
