"""Populates db/policyguard.db from a live scan of the configured AWS account."""
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from db.schema import connect, get_audit_log, save_scan
from demo.simulate_violation import run_pipeline
from lambdas.rule_engine.handler import get_all_resources

if __name__ == "__main__":
    resources = get_all_resources()
    conn = connect()
    previous = get_audit_log(conn)
    classified, remediation, entries = run_pipeline(resources, dry_run=True, chain=previous)
    save_scan(conn, len(resources), classified, remediation, entries[len(previous):])
    print(f"Scanned {len(resources)} AWS resources: stored {len(classified)} violations "
          f"and {len(entries) - len(previous)} audit entries.")
