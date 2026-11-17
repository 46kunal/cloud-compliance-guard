"""Demonstrate why anchoring matters, safely and reversibly.

    python infra/tamper_demo.py forge     # act as an attacker: rewrite one audit event and recompute every hash
    python infra/tamper_demo.py restore   # put the original chain back

Run it against the AWS deployment with the deploy profile and these environment variables set:
    POLICYGUARD_BACKEND=dynamodb  POLICYGUARD_TABLE_PREFIX=policyguard  AWS_DEFAULT_REGION=ap-south-1

What you will see on the Audit trail page after "forge":
  - "Chain integrity: VALID"          the database-only check is fooled, because the attacker recomputed the hashes
  - "Anchor check: MISMATCH"          the locked, KMS-signed receipts still hold the original hashes

"restore" writes the saved original entries back. A backup file is written before anything is changed, and forge
refuses to run if a backup already exists (so a forgery can never overwrite the only copy of the real chain).
This changes the real audit table: use it for the demo, then restore.
"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from db.dynamo_store import CHAIN, DynamoStore, _query_all  # noqa: E402
from boto3.dynamodb.conditions import Key  # noqa: E402
from lambdas.audit_logger.hash_chain import GENESIS, compute_hash, verify_chain  # noqa: E402

BACKUP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tamper_demo_backup.json")


def _raw_items(store):
    return _query_all(store.table("audit_log"), KeyConditionExpression=Key("chain").eq(CHAIN))


def _as_entries(items):
    return [{"id": i["id"], "timestamp": i["timestamp"], "event_type": i["event_type"], "details": json.loads(i["details"]),
             "previous_hash": i["previous_hash"], "entry_hash": i["entry_hash"]} for i in items]


def forge(store=None, backup_path=BACKUP):
    store = store or DynamoStore()
    if os.path.exists(backup_path):
        sys.exit(f"A backup already exists at {backup_path}. Run 'restore' first.")
    items = _raw_items(store)
    if len(items) < 2:
        sys.exit("The audit chain needs at least two entries to demonstrate this. Run a scan first.")
    with open(backup_path, "w", encoding="utf-8") as handle:
        json.dump(items, handle, default=int)
    entries = _as_entries(items)
    entries[0]["details"] = {"rule": "forged", "resource_id": "an attacker rewrote this entry"}
    previous = GENESIS
    for entry in entries:
        entry["previous_hash"] = previous
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        entry["entry_hash"] = compute_hash(body, previous)
        previous = entry["entry_hash"]
    table = store.table("audit_log")
    for item, entry in zip(items, entries):
        table.put_item(Item={**item, "details": json.dumps(entry["details"]), "previous_hash": entry["previous_hash"],
                             "entry_hash": entry["entry_hash"]})
    print(f"Rewrote {len(entries)} entries. verify_chain on the forged chain: {verify_chain(entries)} (fooled).")
    print("Open the Audit trail page: the anchor check should now say MISMATCH. Then run: python infra/tamper_demo.py restore")


def restore(store=None, backup_path=BACKUP):
    store = store or DynamoStore()
    if not os.path.exists(backup_path):
        sys.exit("No backup found, so nothing to restore.")
    with open(backup_path, encoding="utf-8") as handle:
        items = json.load(handle)
    table = store.table("audit_log")
    for item in items:
        table.put_item(Item=item)
    os.remove(backup_path)
    print(f"Restored {len(items)} original entries and removed the backup.")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "forge":
        forge()
    elif command == "restore":
        restore()
    else:
        sys.exit("usage: python infra/tamper_demo.py forge|restore")
