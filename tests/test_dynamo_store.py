"""The DynamoDB backend must behave exactly like the SQLite one (run against moto, no real AWS)."""
import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws

from dashboard import scanner
from db import store
from db.dynamo_store import DynamoStore
from db.schema import connect as sqlite_connect
from lambdas.audit_logger.hash_chain import verify_chain


def _sg():
    return {"resource_type": "security_group", "provider": "aws", "resource_id": "sg-1",
            "permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], "tags": {}}


def _bucket(public):
    return {"resource_type": "object_storage", "provider": "aws", "resource_id": "b1",
            "is_public": public, "encrypted": True, "permissions": [], "tags": {}}


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setattr(scanner, "_account_scope", lambda: "123456789012")
    monkeypatch.setattr(scanner, "_region_scope", lambda: "ap-south-1")
    monkeypatch.setattr(scanner, "remediate_violations", lambda findings: [])


def _backends(tmp_path):
    yield "sqlite", sqlite_connect(str(tmp_path / "t.db"))
    yield "dynamodb", DynamoStore(create=True)


def _lifecycle(conn):
    first = scanner.scan_and_save(conn, [_sg(), _bucket(True)])
    second = scanner.scan_and_save(conn, [_sg(), _bucket(False)])
    third = scanner.scan_and_save(conn, [_sg(), _bucket(True)])
    return first, second, third


@mock_aws
def test_lifecycle_matches_sqlite(tmp_path):
    results = {}
    for name, conn in _backends(tmp_path):
        first, second, third = _lifecycle(conn)
        findings = {(f["rule"], f["resource_id"]): f for f in store.get_findings(conn)}
        results[name] = (
            (first["violations"], first["new"], first["resolved"]),
            (second["violations"], second["new"], second["resolved"]),
            (third["violations"], third["new"], third["resolved"]),
            sorted((k, f["status"]) for k, f in findings.items()),
        )
    assert results["sqlite"] == results["dynamodb"]
    statuses = dict(results["dynamodb"][3])
    assert statuses[("public_storage", "b1")] == "REOPENED"
    assert statuses[("open_admin_ports", "sg-1")] == "ACTIVE"


@mock_aws
def test_audit_chain_valid_and_ordered():
    conn = DynamoStore(create=True)
    _lifecycle(conn)
    entries = store.get_audit_log(conn)
    assert entries and verify_chain(entries)
    assert [e["event_type"] for e in entries][0] == "VIOLATION_DETECTED"


@mock_aws
def test_audit_append_refuses_forked_chain():
    conn = DynamoStore(create=True)
    scanner.scan_and_save(conn, [_sg()])
    from db.dynamo_store import _append_audit_entries
    forged = {"id": "x", "timestamp": "t", "event_type": "E", "details": {}, "previous_hash": "wrong", "entry_hash": "h"}
    with pytest.raises(RuntimeError):
        _append_audit_entries(conn, [forged])
    assert verify_chain(store.get_audit_log(conn))


@mock_aws
def test_evidence_stored_with_hash_and_native_document():
    conn = DynamoStore(create=True)
    scanner.scan_and_save(conn, [_sg()])
    finding = store.get_findings(conn)[0]
    assert finding["evidence_available"]
    evidence = store.get_finding_evidence(conn, finding["id"])
    assert len(evidence) == 1 and len(evidence[0]["evidence_sha256"]) == 64
    raw = conn.table("finding_evidence").scan()["Items"][0]
    assert isinstance(raw["evidence"], dict) and raw["evidence"]["rule"] == "open_admin_ports"


@mock_aws
def test_get_finding_by_id_and_scan_history():
    conn = DynamoStore(create=True)
    _lifecycle(conn)
    finding = store.get_findings(conn)[0]
    assert store.get_finding(conn, finding["id"])["finding_key"] == finding["finding_key"]
    assert store.get_finding(conn, 99999) is None
    scans = store.get_scans(conn)
    assert [s["id"] for s in scans] == [3, 2, 1]
    assert store.get_latest_scan(conn)["status"] == "COMPLETED"


@mock_aws
def test_facade_picks_backend_from_environment(monkeypatch):
    monkeypatch.setenv("POLICYGUARD_BACKEND", "dynamodb")
    DynamoStore(create=True)
    conn = store.connect()
    assert isinstance(conn, DynamoStore)
    assert store.get_latest_scan(conn) is None


# ---- generic documents and admin audit events (used by accounts, controls and incidents) ----
@mock_aws
def test_documents_round_trip_on_both_backends(tmp_path):
    for _name, conn in _backends(tmp_path):
        assert store.list_docs(conn, "controls") == []
        store.put_doc(conn, "controls", "C1", {"id": "C1", "status": "in_progress", "nested": {"a": [1, 2]}})
        store.put_doc(conn, "controls", "C1", {"id": "C1", "status": "attested", "nested": {"a": [1, 2]}})
        store.put_doc(conn, "accounts", "1", {"id": "1"})
        assert store.get_doc(conn, "controls", "C1")["status"] == "attested"
        assert [d["id"] for d in store.list_docs(conn, "controls")] == ["C1"]
        store.delete_doc(conn, "controls", "C1")
        assert store.get_doc(conn, "controls", "C1") is None and len(store.list_docs(conn, "accounts")) == 1


@mock_aws
def test_admin_actions_extend_the_audit_chain_on_both_backends(tmp_path):
    for _name, conn in _backends(tmp_path):
        scanner.scan_and_save(conn, [_sg()])
        before = len(store.get_audit_log(conn))
        store.append_audit_events(conn, [("USER_CREATED", {"actor": "pgadmin", "user": "asha"}),
                                         ("ACCOUNT_ADDED", {"actor": "pgadmin", "account": "1"})])
        chain = store.get_audit_log(conn)
        assert len(chain) == before + 2 and verify_chain(chain)
        assert chain[-1]["event_type"] == "ACCOUNT_ADDED"
