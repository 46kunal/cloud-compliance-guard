"""
End-to-end PolicyGuard demo:
    rule_engine -> risk_classifier -> remediation -> audit_logger

    python demo/simulate_violation.py            # fake resources, no AWS needed
    python demo/simulate_violation.py --live     # scan the real AWS account (needs creds)
    python demo/simulate_violation.py --save     # also store results for the dashboard
    python demo/simulate_violation.py --tamper   # show hash-chain tamper detection

Remediation is always dry-run unless POLICYGUARD_DRY_RUN=false AND the resource is allowlisted.
"""
import argparse
import copy
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from lambdas.rule_engine.handler import get_all_resources, run_rule_engine
from lambdas.risk_classifier.handler import classify_violations
from lambdas.remediation.handler import remediate_violations
from lambdas.audit_logger.handler import build_audit_log
from lambdas.audit_logger.hash_chain import verify_chain
from lambdas.audit_logger.blockchain_anchor import anchor_hash


def _res(resource_type, resource_id, **extra):
    base = {"resource_type": resource_type, "provider": "aws", "resource_id": resource_id,
            "is_public": False, "encrypted": True, "permissions": [], "tags": {}}
    return {**base, **extra}


FAKE_RESOURCES = [
    _res("object_storage", "customer-data-public", is_public=True, encrypted=False),
    _res("object_storage", "payment-logs", encrypted=False),
    _res("object_storage", "secure-backups"),
    _res("iam_policy", "arn:aws:iam::123456789012:policy/AdminEverything",
         permissions=[{"Effect": "Allow", "Action": "*", "Resource": "*"}]),
    _res("iam_policy", "arn:aws:iam::123456789012:policy/ReadOnlyS3",
         permissions=[{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*"}]),
    _res("iam_user", "intern-dev", has_console_access=True, mfa_enabled=False),
    _res("iam_user", "ops-admin", has_console_access=True, mfa_enabled=True),
]


def run_pipeline(resources: list, dry_run: bool = None, chain: list = None):
    classified = classify_violations(run_rule_engine(resources))
    remediation = remediate_violations(classified, dry_run=dry_run)
    entries = build_audit_log(classified, remediation, chain)
    return classified, remediation, entries


def main():
    parser = argparse.ArgumentParser(description="PolicyGuard end-to-end demo")
    parser.add_argument("--live", action="store_true", help="scan real AWS resources instead of fake ones")
    parser.add_argument("--save", action="store_true", help="store results in db/policyguard.db for the dashboard")
    parser.add_argument("--tamper", action="store_true", help="demonstrate tamper detection on the audit chain")
    args = parser.parse_args()

    resources = get_all_resources() if args.live else FAKE_RESOURCES
    source = "LIVE AWS" if args.live else "simulated"
    print(f"=== PolicyGuard scan: {len(resources)} resources ({source}) ===")
    print()

    conn = None
    previous_chain = []
    if args.save:
        from db.schema import connect, get_audit_log
        conn = connect()
        previous_chain = get_audit_log(conn)

    classified, remediation, entries = run_pipeline(resources, chain=previous_chain)
    new_entries = entries[len(previous_chain):]

    for v in classified:
        print(f"[DETECT]    {v['rule']:<20} on {v['resource_id']}")
    print()
    for v in classified:
        print(f"[CLASSIFY]  {v['severity']:<6} | {v['clause']} | {v['resource_id']}")
    print()
    for r in remediation:
        mode = "DRY-RUN" if r.get("dry_run") else "LIVE"
        print(f"[REMEDIATE] {mode:<7} | {r['action']:<22} | {r['resource_id']} | {r.get('message', '')}")
    print()
    for e in new_entries:
        print(f"[AUDIT]     {e['event_type']:<18} hash={e['entry_hash'][:16]}... prev={e['previous_hash'][:16]}")
    print(f"[AUDIT]     Chain of {len(entries)} entries valid: {verify_chain(entries)}")
    if entries:
        anchor_hash(entries[-1]["entry_hash"])

    if args.tamper and entries:
        tampered = copy.deepcopy(entries)
        tampered[0]["details"]["severity"] = "LOW"
        print(f"[AUDIT]     After editing entry 1 severity to LOW, chain valid: {verify_chain(tampered)}  <- tampering detected")

    if conn is not None:
        from db.schema import save_scan
        save_scan(conn, len(resources), classified, remediation, new_entries)
        print()
        print("[SAVE] Results stored in db/policyguard.db. Now run: python dashboard/app.py")


if __name__ == "__main__":
    main()
