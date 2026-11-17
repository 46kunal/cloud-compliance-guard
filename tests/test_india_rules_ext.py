"""Second batch of India-profile rules: unit behaviour, real collectors on moto, and audit trail for them."""
import json

import pytest

from lambdas.rule_engine.handler import run_rule_engine
from lambdas.rule_engine.rules import (backup_enabled, log_location_india, retention_lifecycle, root_mfa,
                                       s3_access_logging, stale_access_keys, vpc_flow_logs)


def bucket(**kw):
    return {"resource_type": "object_storage", "resource_id": "b", "provider": "aws", "tags": {}, **kw}


PERSONAL = {"handles_personal_data": "true"}


@pytest.mark.parametrize("module,bad,good,unknown", [
    (vpc_flow_logs, {"resource_type": "cloudtrail_config", "vpcs_without_flow_logs": ["vpc-1"]},
     {"resource_type": "cloudtrail_config", "vpcs_without_flow_logs": []}, {"resource_type": "cloudtrail_config"}),
    (root_mfa, {"resource_type": "iam_account", "root_mfa_enabled": False, "root_access_keys_present": False},
     {"resource_type": "iam_account", "root_mfa_enabled": True, "root_access_keys_present": False},
     {"resource_type": "iam_account"}),
    (stale_access_keys, {"resource_type": "iam_user", "stale_access_keys": [{"key_suffix": "ABCD", "age_days": 120}]},
     {"resource_type": "iam_user", "stale_access_keys": []}, {"resource_type": "iam_user"}),
    (s3_access_logging, bucket(tags=PERSONAL, logging_enabled=False), bucket(tags=PERSONAL, logging_enabled=True),
     bucket(tags=PERSONAL)),
    (retention_lifecycle, bucket(tags=PERSONAL, lifecycle_defined=False), bucket(tags=PERSONAL, lifecycle_defined=True),
     bucket(tags=PERSONAL)),
    (backup_enabled, {"resource_type": "database", "backup_enabled": False},
     {"resource_type": "database", "backup_enabled": True}, {"resource_type": "database"}),
    (log_location_india, {"resource_type": "cloudtrail_config", "trail_logs_outside_india": [{"trail": "t"}]},
     {"resource_type": "cloudtrail_config", "trail_logs_outside_india": []}, {"resource_type": "cloudtrail_config"}),
])
def test_rule_flags_bad_passes_good_skips_unknown(module, bad, good, unknown):
    assert module.check(bad)["compliant"] is False
    assert module.check(good)["compliant"] is True
    assert module.check(unknown)["compliant"] is True


def test_root_with_access_keys_fails_even_when_mfa_is_on():
    resource = {"resource_type": "iam_account", "root_mfa_enabled": True, "root_access_keys_present": True}
    assert root_mfa.check(resource)["compliant"] is False


def test_logging_and_lifecycle_only_apply_to_personal_data_buckets():
    plain = bucket(logging_enabled=False, lifecycle_defined=False)
    assert s3_access_logging.check(plain)["compliant"] is True
    assert retention_lifecycle.check(plain)["compliant"] is True


@pytest.mark.parametrize("resource_type", ["database", "nosql_table", "file_storage", "block_storage"])
def test_backup_rule_covers_every_data_store_type(resource_type):
    assert backup_enabled.check({"resource_type": resource_type, "backup_enabled": False})["compliant"] is False


def test_existing_rules_now_cover_databases(monkeypatch):
    monkeypatch.setenv("POLICYGUARD_PROFILE", "india")
    db = {"resource_type": "database", "resource_id": "db1", "provider": "aws", "tags": {}, "is_public": True,
          "encrypted": False, "backup_enabled": True, "region": "us-east-1"}
    assert {v["rule"] for v in run_rule_engine([db])} == {"public_storage", "encryption_at_rest", "data_residency_india"}


# ---- collectors against moto ----
moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")


@pytest.fixture
def aws(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "ap-south-1",
                       "POLICYGUARD_PROFILE": "india"}.items():
        monkeypatch.setenv(key, value)
    with moto.mock_aws():
        yield


def test_iam_collector_reports_root_summary_and_stale_keys(aws, monkeypatch):
    from lambdas.rule_engine.handler import get_normalized_iam_resources
    iam = boto3.client("iam")
    iam.create_user(UserName="ravi")
    iam.create_access_key(UserName="ravi")
    monkeypatch.setenv("POLICYGUARD_KEY_MAX_AGE_DAYS", "0")      # a brand-new key counts as stale
    resources = get_normalized_iam_resources({})
    account = next(r for r in resources if r["resource_type"] == "iam_account")
    user = next(r for r in resources if r["resource_id"] == "ravi")
    assert account["root_mfa_enabled"] is False and account["root_access_keys_present"] is False
    assert len(user["stale_access_keys"]) == 1 and user["stale_access_keys"][0]["age_days"] >= 0
    rules = {v["rule"] for v in run_rule_engine(resources)}
    assert {"root_mfa", "stale_access_keys"} <= rules

    monkeypatch.setenv("POLICYGUARD_KEY_MAX_AGE_DAYS", "90")
    user = next(r for r in get_normalized_iam_resources({}) if r["resource_id"] == "ravi")
    assert user["stale_access_keys"] == []


def test_s3_collector_reports_logging_and_lifecycle(aws):
    from lambdas.rule_engine.handler import get_normalized_s3_resources
    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(Bucket="pii", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    s3.put_bucket_tagging(Bucket="pii", Tagging={"TagSet": [{"Key": "handles_personal_data", "Value": "true"}]})
    s3.create_bucket(Bucket="tidy", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    s3.put_bucket_tagging(Bucket="tidy", Tagging={"TagSet": [{"Key": "handles_personal_data", "Value": "true"}]})
    s3.put_bucket_lifecycle_configuration(Bucket="tidy", LifecycleConfiguration={"Rules": [
        {"ID": "expire", "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 365}}]})
    by_id = {r["resource_id"]: r for r in get_normalized_s3_resources({})}
    assert by_id["pii"]["logging_enabled"] is False and by_id["pii"]["lifecycle_defined"] is False
    assert by_id["tidy"]["lifecycle_defined"] is True
    flagged = {(v["rule"], v["resource_id"]) for v in run_rule_engine(list(by_id.values()))}
    assert ("retention_lifecycle", "pii") in flagged and ("retention_lifecycle", "tidy") not in flagged
    assert ("s3_access_logging", "pii") in flagged


def test_account_collector_reports_flow_logs_and_trail_location(aws):
    from lambdas.rule_engine.handler import get_normalized_cloudtrail_resources
    ec2 = boto3.client("ec2", region_name="ap-south-1")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="trail-logs-us")
    boto3.client("cloudtrail", region_name="ap-south-1").create_trail(Name="main-trail", S3BucketName="trail-logs-us")

    account = get_normalized_cloudtrail_resources({})[0]
    assert vpc in account["vpcs_without_flow_logs"]
    assert account["trail_logs_outside_india"] == [
        {"trail": "main-trail", "bucket": "trail-logs-us", "bucket_region": "us-east-1", "log_group_region": None}]

    s3.create_bucket(Bucket="flow-logs")
    ec2.create_flow_logs(ResourceIds=[vpc], ResourceType="VPC", TrafficType="ALL", LogDestinationType="s3",
                         LogDestination="arn:aws:s3:::flow-logs")
    assert get_normalized_cloudtrail_resources({})[0]["vpcs_without_flow_logs"] == []


def test_data_store_collectors_report_backups_encryption_and_region(aws):
    from lambdas.rule_engine.handler import (get_normalized_dynamodb_resources, get_normalized_efs_resources,
                                             get_normalized_ec2_resources, get_normalized_rds_resources)
    boto3.client("rds", region_name="ap-south-1").create_db_instance(
        DBInstanceIdentifier="orders", DBInstanceClass="db.t3.micro", Engine="postgres", MasterUsername="u",
        MasterUserPassword="long-test-password-1", AllocatedStorage=20, BackupRetentionPeriod=0, StorageEncrypted=False)
    boto3.client("dynamodb", region_name="ap-south-1").create_table(
        TableName="items", AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}], BillingMode="PAY_PER_REQUEST")
    boto3.client("efs", region_name="ap-south-1").create_file_system(Encrypted=False, CreationToken="t1")
    boto3.client("ec2", region_name="ap-south-1").create_volume(AvailabilityZone="ap-south-1a", Size=8, Encrypted=False)

    report = {}
    resources = (get_normalized_rds_resources(report) + get_normalized_dynamodb_resources(report)
                 + get_normalized_efs_resources(report) + [r for r in get_normalized_ec2_resources(report)
                                                          if r["resource_type"] == "block_storage"])
    assert {r["resource_type"] for r in resources} == {"database", "nosql_table", "file_storage", "block_storage"}
    assert all(r["region"] == "ap-south-1" and r["backup_enabled"] is False for r in resources)
    assert {name: report[name]["status"] for name in ("rds", "dynamodb", "efs", "ec2")} == {
        "rds": "SUCCESS", "dynamodb": "SUCCESS", "efs": "SUCCESS", "ec2": "SUCCESS"}
    found = {(v["rule"], v["resource_type"]) for v in run_rule_engine(resources)}
    for rtype in ("database", "nosql_table", "file_storage", "block_storage"):
        assert ("backup_enabled", rtype) in found
    assert ("encryption_at_rest", "database") in found and ("encryption_at_rest", "nosql_table") not in found


# ---- audit trail covers resolutions for India rules (was missing before the shared service map) ----
def test_resolving_an_india_rule_finding_is_recorded_in_the_audit_chain(tmp_path, monkeypatch):
    from dashboard import scanner
    from db.schema import connect, get_audit_log
    from lambdas.audit_logger.hash_chain import verify_chain
    monkeypatch.setenv("POLICYGUARD_PROFILE", "india")
    monkeypatch.setattr(scanner, "_account_scope", lambda: "123456789012")
    monkeypatch.setattr(scanner, "_region_scope", lambda: "ap-south-1")
    monkeypatch.setattr(scanner, "remediate_violations", lambda findings: [])
    conn = connect(str(tmp_path / "t.db"))
    weak = bucket(resource_id="logs", region="ap-south-1", encrypted=True, tls_enforced=False)
    strong = dict(weak, tls_enforced=True)
    scanner.scan_and_save(conn, [weak])
    scanner.scan_and_save(conn, [strong])
    chain = get_audit_log(conn)
    assert [e["event_type"] for e in chain] == ["VIOLATION_DETECTED", "VIOLATION_RESOLVED"]
    assert chain[1]["details"]["rule"] == "tls_enforcement" and verify_chain(chain)
