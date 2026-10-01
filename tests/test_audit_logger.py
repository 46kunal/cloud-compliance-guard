import copy
import json

from lambdas.audit_logger.hash_chain import GENESIS, append_entry, verify_chain
from lambdas.audit_logger.handler import build_audit_log, lambda_handler
from lambdas.audit_logger.blockchain_anchor import anchor_hash


def _chain(n=3):
    entries, prev = [], GENESIS
    for i in range(n):
        e = append_entry("VIOLATION_DETECTED", {"rule": "public_storage", "resource_id": f"b{i}"}, prev)
        entries.append(e)
        prev = e["entry_hash"]
    return entries


def test_first_entry_uses_genesis():
    e = append_entry("X", {}, GENESIS)
    assert e["previous_hash"] == "GENESIS"
    assert set(e) == {"id", "timestamp", "event_type", "details", "previous_hash", "entry_hash"}
    assert e["timestamp"].endswith("+00:00")


def test_three_entry_chain_valid():
    assert verify_chain(_chain(3)) is True


def test_tampered_details_detected():
    chain = _chain(3)
    chain[1]["details"]["resource_id"] = "something-else"
    assert verify_chain(chain) is False


def test_reordered_or_removed_entries_detected():
    chain = _chain(3)
    assert verify_chain([chain[0], chain[2]]) is False
    assert verify_chain(list(reversed(chain))) is False


def test_build_audit_log_extends_existing_chain_without_mutation():
    first = build_audit_log([{"rule": "a"}], [{"action": "x"}])
    snapshot = copy.deepcopy(first)
    extended = build_audit_log([{"rule": "b"}], [], chain=first)
    assert first == snapshot
    assert len(extended) == 3 and verify_chain(extended)


def test_lambda_handler_returns_valid_chain():
    body = json.loads(lambda_handler({"violations": [{"rule": "a"}]}, None)["body"])
    assert body["chain_valid"] is True and len(body["entries"]) == 1


def test_blockchain_anchor_noop_when_unconfigured(monkeypatch):
    monkeypatch.delenv("WEB3_RPC_URL", raising=False)
    assert anchor_hash("ab" * 32)["anchored"] is False
