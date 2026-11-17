"""Audit anchoring on moto: receipts are signed and locked, and rewriting the chain is detected."""
import copy

import pytest

moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")

from lambdas.audit_logger import anchor_store
from lambdas.audit_logger.hash_chain import GENESIS, append_entry, compute_hash, verify_chain


def make_chain(n=4):
    entries, previous = [], GENESIS
    for i in range(n):
        entry = append_entry("VIOLATION_DETECTED", {"rule": f"r{i}", "resource_id": f"res{i}"}, previous)
        entries.append(entry)
        previous = entry["entry_hash"]
    return entries


def rewrite_everything(entries, index, new_details):
    """What an attacker with database access would do: change one entry and recompute every hash after it."""
    forged, previous = copy.deepcopy(entries), GENESIS
    for i, entry in enumerate(forged):
        if i == index:
            entry["details"] = new_details
        entry["previous_hash"] = previous
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        entry["entry_hash"] = compute_hash(body, previous)
        previous = entry["entry_hash"]
    return forged


@pytest.fixture
def aws(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "ap-south-1"}.items():
        monkeypatch.setenv(key, value)
    with moto.mock_aws():
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="anchors", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
                         ObjectLockEnabledForBucket=True)
        key = boto3.client("kms").create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")["KeyMetadata"]["KeyId"]
        monkeypatch.setenv("ANCHOR_BUCKET", "anchors")
        monkeypatch.setenv("ANCHOR_KMS_KEY_ID", key)
        yield key


def test_not_configured_is_a_safe_noop(monkeypatch):
    monkeypatch.delenv("ANCHOR_BUCKET", raising=False)
    assert anchor_store.anchor(make_chain()) == {"anchored": False, "reason": "not configured"}


def test_anchor_writes_a_signed_locked_receipt(aws):
    chain = make_chain()
    result = anchor_store.anchor(chain, scan_id=7)
    assert result["anchored"] and result["sequence"] == 4 and result["lock_mode"] == "GOVERNANCE"
    stored = anchor_store.list_anchors()
    assert len(stored) == 1 and stored[0]["receipt"]["head_hash"] == chain[-1]["entry_hash"]
    assert stored[0]["receipt"]["scan_id"] == 7 and stored[0]["locked_until"]
    s3 = boto3.client("s3")
    head = s3.head_object(Bucket="anchors", Key=stored[0]["s3_key"])
    assert head["ObjectLockMode"] == "GOVERNANCE"


def test_locked_receipt_cannot_be_deleted_without_bypass(aws):
    anchor_store.anchor(make_chain())
    s3 = boto3.client("s3")
    key = anchor_store.list_anchors()[0]["s3_key"]
    version = s3.head_object(Bucket="anchors", Key=key)["VersionId"]
    with pytest.raises(Exception):
        s3.delete_object(Bucket="anchors", Key=key, VersionId=version)


def test_no_new_entries_means_no_new_receipt(aws):
    chain = make_chain()
    assert anchor_store.anchor(chain)["anchored"]
    again = anchor_store.anchor(chain)
    assert not again["anchored"] and "no new" in again["reason"]
    chain.append(append_entry("REMEDIATION", {"action": "x"}, chain[-1]["entry_hash"]))
    assert anchor_store.anchor(chain)["anchored"]
    assert len(anchor_store.list_anchors()) == 2


def test_untouched_chain_verifies(aws):
    chain = make_chain()
    anchor_store.anchor(chain)
    chain.append(append_entry("REMEDIATION", {"action": "x"}, chain[-1]["entry_hash"]))
    report = anchor_store.verify(chain, anchor_store.list_anchors())
    assert report["status"] == "VERIFIED" and report["entries_after_last_anchor"] == 1


def test_rewriting_the_whole_chain_is_detected_even_though_it_still_looks_valid(aws):
    chain = make_chain()
    anchor_store.anchor(chain)
    forged = rewrite_everything(chain, 1, {"rule": "innocent", "resource_id": "nothing-to-see"})
    assert verify_chain(forged) is True                      # the database-only check is fooled
    report = anchor_store.verify(forged, anchor_store.list_anchors())
    assert report["status"] == "MISMATCH"
    assert report["anchors"][0]["matches_chain"] is False and "rewritten" in report["anchors"][0]["reason"]


def test_removing_entries_is_detected(aws):
    chain = make_chain()
    anchor_store.anchor(chain)
    report = anchor_store.verify(chain[:2], anchor_store.list_anchors())
    assert report["status"] == "MISMATCH" and "shorter" in report["anchors"][0]["reason"]


def test_a_forged_receipt_fails_signature_check(aws):
    chain = make_chain()
    anchor_store.anchor(chain)
    stored = anchor_store.list_anchors()
    stored[0]["receipt"]["head_hash"] = "0" * 64             # attacker edits the receipt text
    report = anchor_store.verify(chain, stored)
    assert report["anchors"][0]["signature_valid"] is False and report["status"] == "MISMATCH"


def test_no_anchors_yet_is_reported_plainly(aws):
    assert anchor_store.verify(make_chain(), [])["status"] == "NO_ANCHORS"


def test_dashboard_reports_anchor_status_and_flags_a_rewritten_chain(aws, monkeypatch, tmp_path):
    """End to end through the API: scan writes a receipt; rewriting the stored chain turns the status to MISMATCH."""
    import json
    from dashboard import scanner
    from dashboard.app import create_app
    from db import schema
    from db.store import get_audit_log
    monkeypatch.setenv("POLICYGUARD_AUTH", "off")
    monkeypatch.setattr(scanner, "_account_scope", lambda: "123456789012")
    monkeypatch.setattr(scanner, "_region_scope", lambda: "ap-south-1")
    monkeypatch.setattr(scanner, "remediate_violations", lambda findings: [])
    db_path = str(tmp_path / "a.db")
    monkeypatch.setattr("db.schema.DB_PATH", db_path)
    conn = schema.connect(db_path)
    sg = {"resource_type": "security_group", "provider": "aws", "resource_id": "sg-1", "region": "ap-south-1",
          "permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], "tags": {}}
    scanner.scan_and_save(conn, [sg])
    anchor_store.anchor(get_audit_log(conn))
    client = create_app().test_client()
    data = client.get("/api/audit-anchors").get_json()
    assert data["configured"] and data["status"] == "VERIFIED" and data["lock_mode"] == "GOVERNANCE"

    # An attacker edits the first stored event and recomputes the hashes in the database.
    rows = conn.execute("SELECT seq, details FROM audit_log ORDER BY seq").fetchall()
    forged = rewrite_everything(get_audit_log(conn), 0, {"rule": "innocent", "resource_id": "x"})
    for row, entry in zip(rows, forged):
        conn.execute("UPDATE audit_log SET details=?, previous_hash=?, entry_hash=? WHERE seq=?",
                     (json.dumps(entry["details"]), entry["previous_hash"], entry["entry_hash"], row["seq"]))
    conn.commit()
    assert client.get("/api/audit-log").get_json()["chain_valid"] is True   # the old check is fooled
    assert client.get("/api/audit-anchors").get_json()["status"] == "MISMATCH"   # the anchor is not


def test_a_server_that_only_sets_aws_region_can_still_call_kms_and_s3(monkeypatch, tmp_path):
    """Regression: the EC2 servers set AWS_REGION but not AWS_DEFAULT_REGION, so the anchors API returned 502
    ('You must specify a region'). The app now copies AWS_REGION into AWS_DEFAULT_REGION at startup."""
    import importlib
    import os
    for name in ("AWS_DEFAULT_REGION", "AWS_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))            # ignore this machine's region setting
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-creds"))
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_REGION": "ap-south-1"}.items():
        monkeypatch.setenv(key, value)
    with moto.mock_aws():
        s3 = boto3.client("s3", region_name="ap-south-1")
        s3.create_bucket(Bucket="anchors", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"}, ObjectLockEnabledForBucket=True)
        key = boto3.client("kms", region_name="ap-south-1").create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")["KeyMetadata"]["KeyId"]
        monkeypatch.setenv("ANCHOR_BUCKET", "anchors")
        monkeypatch.setenv("ANCHOR_KMS_KEY_ID", key)
        monkeypatch.setenv("POLICYGUARD_AUTH", "off")
        monkeypatch.setattr("db.schema.DB_PATH", str(tmp_path / "r.db"))
        import dashboard.app as app_module
        importlib.reload(app_module)                                              # runs the startup shim
        assert os.environ.get("AWS_DEFAULT_REGION") == "ap-south-1"
        client = app_module.create_app().test_client()
        data = client.get("/api/audit-anchors")
        assert data.status_code == 200 and data.get_json()["status"] == "NO_ANCHORS"
        s3_client, kms_client = anchor_store._clients()
        assert s3_client.meta.region_name == "ap-south-1" and kms_client.meta.region_name == "ap-south-1"
