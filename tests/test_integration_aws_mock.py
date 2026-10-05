"""
Integration test: real boto3 collectors + full pipeline against an in-memory AWS (moto).
Generates random misconfigurations and checks detected counts match exactly.
"""
import json
import random
from collections import Counter

import pytest

moto = pytest.importorskip("moto")
import boto3

from lambdas.rule_engine.handler import get_all_resources, run_rule_engine
from lambdas.risk_classifier.handler import classify_violations
from lambdas.remediation.handler import remediate_violations
from lambdas.audit_logger.handler import build_audit_log
from lambdas.audit_logger.hash_chain import verify_chain


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        yield


def _add_compliant_cloudtrail() -> None:
    """A mocked account has no trail, which the cloudtrail_enabled rule rightly flags; add a good one."""
    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="trail-logs-bucket")
    s3.put_bucket_encryption(Bucket="trail-logs-bucket", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    ct = boto3.client("cloudtrail")
    ct.create_trail(Name="main-trail", S3BucketName="trail-logs-bucket", IsMultiRegionTrail=True)
    ct.start_logging(Name="main-trail")


def _populate(rng, n_buckets=40, n_policies=20, n_users=30) -> Counter:
    expected = Counter()
    s3, iam = boto3.client("s3"), boto3.client("iam")
    _add_compliant_cloudtrail()

    for i in range(n_buckets):
        name = f"test-bucket-{i:04d}"
        s3.create_bucket(Bucket=name)
        public, blocked = rng.random() < 0.3, rng.random() < 0.3
        if public:
            s3.put_bucket_policy(Bucket=name, Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{name}/*"}]}))
        if blocked:
            s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        expected["public_storage"] += public and not blocked
        if rng.random() < 0.7:
            s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
        else:
            expected["encryption_at_rest"] += 1

    for i in range(n_policies):
        wildcard = rng.random() < 0.3
        action = rng.choice(["*", "s3:*"]) if wildcard else "s3:GetObject"
        resource = "*" if wildcard else "arn:aws:s3:::reports/*"
        iam.create_policy(PolicyName=f"test-policy-{i:03d}", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}]}))
        expected["wildcard_permission"] += wildcard

    for i in range(n_users):
        user = f"test-user-{i:03d}"
        iam.create_user(UserName=user)
        console, mfa = rng.random() < 0.7, rng.random() < 0.5
        if console:
            iam.create_login_profile(UserName=user, Password="Test-Passw0rd!")
        if mfa:
            serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=user)["VirtualMFADevice"]["SerialNumber"]
            iam.enable_mfa_device(UserName=user, SerialNumber=serial,
                                  AuthenticationCode1="123456", AuthenticationCode2="654321")
        expected["mfa_required"] += console and not mfa

    return +expected  # drop zero counts


def test_collectors_detect_exactly_the_generated_misconfigurations(aws):
    expected = _populate(random.Random(7))
    resources = get_all_resources()
    # Exclude resources that are not generated: moto's default VPC security group, the CloudTrail
    # account resource, and the trail's own log bucket
    generated = [r for r in resources
                 if r["resource_type"] not in ("security_group", "cloudtrail_config")
                 and r["resource_id"] != "trail-logs-bucket"]
    assert len(generated) == 40 + 20 + 30
    assert Counter(v["rule"] for v in run_rule_engine(resources)) == expected


def test_live_scanner_records_detected_and_resolved(aws, tmp_path):
    from db.schema import connect, get_audit_log, get_violations
    from dashboard.scanner import scan_and_save

    _add_compliant_cloudtrail()
    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="live-demo-bucket")
    s3.put_bucket_encryption(Bucket="live-demo-bucket", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    s3.put_bucket_policy(Bucket="live-demo-bucket", Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::live-demo-bucket/*"}]}))
    conn = connect(str(tmp_path / "live.db"))

    assert scan_and_save(conn)["new"] == 1                 # made public -> detected
    assert scan_and_save(conn)["new"] == 0                 # unchanged -> no duplicate audit entries
    s3.delete_bucket_policy(Bucket="live-demo-bucket")     # "fixed in the console"
    result = scan_and_save(conn)

    assert result["resolved"] == 1 and get_violations(conn) == []
    chain = get_audit_log(conn)
    assert [e["event_type"] for e in chain] == ["VIOLATION_DETECTED", "REMEDIATION", "VIOLATION_RESOLVED"]
    assert verify_chain(chain)


def test_full_pipeline_on_mocked_account(aws):
    _populate(random.Random(11))
    classified = classify_violations(run_rule_engine(get_all_resources()))
    remediation = remediate_violations(classified, dry_run=True)
    entries = build_audit_log(classified, remediation)
    assert all(r["dry_run"] for r in remediation)
    assert len(entries) == 2 * len(classified)
    assert verify_chain(entries)
