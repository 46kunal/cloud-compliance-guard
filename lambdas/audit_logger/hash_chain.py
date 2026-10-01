"""
Tamper-evident hash chain for the audit log.

entry_hash = SHA-256( json.dumps(entry_without_hash, sort_keys=True) + previous_hash )
The first entry's previous_hash is "GENESIS". Changing any field of any entry
(or reordering/removing entries) breaks every hash after it.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone

GENESIS = "GENESIS"


def compute_hash(entry_without_hash: dict, previous_hash: str) -> str:
    payload = json.dumps(entry_without_hash, sort_keys=True, default=str) + previous_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_entry(event_type: str, details: dict, previous_hash: str = GENESIS) -> dict:
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "details": details,
        "previous_hash": previous_hash,
    }
    entry["entry_hash"] = compute_hash(entry, previous_hash)
    return entry


def verify_chain(entries: list) -> bool:
    expected_previous = GENESIS
    for entry in entries:
        if entry.get("previous_hash") != expected_previous:
            return False
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        if compute_hash(body, expected_previous) != entry.get("entry_hash"):
            return False
        expected_previous = entry["entry_hash"]
    return True
