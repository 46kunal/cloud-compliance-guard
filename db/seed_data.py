"""Seeds db/policyguard.db with a simulated scan so the dashboard has data without AWS."""
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from db.schema import connect, get_audit_log, save_scan
from demo.simulate_violation import FAKE_RESOURCES, run_pipeline

if __name__ == "__main__":
    conn = connect()
    previous = get_audit_log(conn)
    classified, remediation, entries = run_pipeline(FAKE_RESOURCES, dry_run=True, chain=previous)
    save_scan(conn, len(FAKE_RESOURCES), classified, remediation, entries[len(previous):])
    print(f"Seeded {len(classified)} violations and {len(entries) - len(previous)} audit entries.")
