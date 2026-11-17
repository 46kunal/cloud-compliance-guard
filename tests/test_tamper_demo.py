"""The tamper demo forges the chain reversibly: anchors flag it, and restore brings back the original."""
import sys

import pytest

moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")
from moto import mock_aws

sys.path.insert(0, "infra")
import tamper_demo  # noqa: E402

from dashboard import scanner  # noqa: E402
from db import store  # noqa: E402
from db.dynamo_store import DynamoStore  # noqa: E402
from lambdas.audit_logger import anchor_store  # noqa: E402
from lambdas.audit_logger.hash_chain import verify_chain  # noqa: E402


def _sg(rid):
    return {"resource_type": "security_group", "provider": "aws", "resource_id": rid, "region": "ap-south-1",
            "permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], "tags": {}}


@mock_aws
def test_forge_fools_the_chain_but_not_the_anchors_and_restore_undoes_it(monkeypatch, tmp_path):
    for key, value in {"AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t", "AWS_DEFAULT_REGION": "ap-south-1"}.items():
        monkeypatch.setenv(key, value)
    boto3.client("s3").create_bucket(Bucket="anchors", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
                                     ObjectLockEnabledForBucket=True)
    key = boto3.client("kms").create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")["KeyMetadata"]["KeyId"]
    monkeypatch.setenv("ANCHOR_BUCKET", "anchors")
    monkeypatch.setenv("ANCHOR_KMS_KEY_ID", key)
    monkeypatch.setattr(scanner, "_account_scope", lambda: "123456789012")
    monkeypatch.setattr(scanner, "_region_scope", lambda: "ap-south-1")
    monkeypatch.setattr(scanner, "remediate_violations", lambda f: [])

    conn = DynamoStore(create=True)
    scanner.scan_and_save(conn, [_sg("sg-1"), _sg("sg-2")])
    original = store.get_audit_log(conn)
    assert len(original) >= 2
    anchor_store.anchor(original)
    backup = str(tmp_path / "backup.json")

    tamper_demo.forge(conn, backup)
    forged = store.get_audit_log(conn)
    assert forged != original and verify_chain(forged) is True                       # database-only check is fooled
    assert anchor_store.verify(forged, anchor_store.list_anchors())["status"] == "MISMATCH"

    with pytest.raises(SystemExit):
        tamper_demo.forge(conn, backup)                                               # never overwrite the only backup

    tamper_demo.restore(conn, backup)
    assert store.get_audit_log(conn) == original
    assert anchor_store.verify(store.get_audit_log(conn), anchor_store.list_anchors())["status"] == "VERIFIED"
