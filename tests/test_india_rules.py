"""India-profile rules: unit behaviour, profile gating, real collectors against moto, and measured accuracy."""
import json
import random

import pytest

from lambdas.rule_engine.handler import run_rule_engine
from lambdas.rule_engine.rules import (data_residency_india, log_retention_180d, log_retention_365d,
                                       s3_versioning, threat_detection_enabled, tls_enforcement)


def bucket(**kw):
    return {"resource_type": "object_storage", "resource_id": "b", "provider": "aws", "tags": {}, **kw}


def account(**kw):
    return {"resource_type": "cloudtrail_config", "resource_id": "cloudtrail:account-wide", "provider": "aws",
            "tags": {}, **kw}


# ---- unit: each rule flags the bad case, passes the good case, and skips what was not collected ----
@pytest.mark.parametrize("module,bad,good,unknown", [
    (data_residency_india, bucket(region="us-east-1"), bucket(region="ap-south-1"), bucket()),
    (tls_enforcement, bucket(tls_enforced=False), bucket(tls_enforced=True), bucket()),
    (s3_versioning, bucket(versioning_enabled=False), bucket(versioning_enabled=True), bucket()),
    (log_retention_180d, account(short_retention_log_groups=[{"name": "a", "days": 30}]),
     account(short_retention_log_groups=[{"name": "a", "days": 200}]), account()),
    (log_retention_365d, account(short_retention_log_groups=[{"name": "a", "days": 200}]),
     account(short_retention_log_groups=[]), account()),
    (threat_detection_enabled, account(guardduty_enabled=False), account(guardduty_enabled=True), account()),
])
def test_rule_flags_bad_passes_good_skips_unknown(module, bad, good, unknown):
    assert module.check(bad)["compliant"] is False
    assert module.check(good)["compliant"] is True
    assert module.check(unknown)["compliant"] is True


def test_data_residency_covers_both_indian_regions_and_ignores_other_types():
    assert data_residency_india.check(bucket(region="ap-south-2"))["compliant"] is True
    assert data_residency_india.check(bucket(region="eu-west-1"))["compliant"] is False
    iam = {"resource_type": "iam_user", "resource_id": "u", "region": "us-east-1"}
    assert data_residency_india.check(iam)["compliant"] is True


def test_180_day_rule_passes_a_90_day_boundary_correctly():
    just_under = account(short_retention_log_groups=[{"name": "a", "days": 179}])
    exactly = account(short_retention_log_groups=[{"name": "a", "days": 180}])
    assert log_retention_180d.check(just_under)["compliant"] is False
    assert log_retention_180d.check(exactly)["compliant"] is True


# ---- profile gating ----
def test_india_rules_only_run_under_india_profile(monkeypatch):
    resources = [bucket(region="us-east-1", encrypted=True, is_public=False)]
    monkeypatch.delenv("POLICYGUARD_PROFILE", raising=False)
    assert run_rule_engine(resources) == []
    monkeypatch.setenv("POLICYGUARD_PROFILE", "india")
    assert [v["rule"] for v in run_rule_engine(resources)] == ["data_residency_india"]


def test_india_violation_carries_india_clause(monkeypatch):
    monkeypatch.setenv("POLICYGUARD_PROFILE", "india")
    log = run_rule_engine([account(short_retention_log_groups=[{"name": "a", "days": 30}],
                                   active_multi_region_trail=True)])
    clauses = {v["rule"]: v["clause"] for v in log}
    assert "CERT-In" in clauses["log_retention_180d"]
    assert "Rule 6" in clauses["log_retention_365d"]


# ---- collectors against moto ----
moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")


@pytest.fixture
def aws(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "ap-south-1"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("POLICYGUARD_PROFILE", "india")
    with moto.mock_aws():
        yield


TLS_POLICY = lambda name: json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Deny", "Principal": "*", "Action": "s3:*",
    "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})


def test_s3_collector_reports_region_tls_and_versioning(aws):
    from lambdas.rule_engine.handler import get_normalized_s3_resources
    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(Bucket="good", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    s3.put_bucket_policy(Bucket="good", Policy=TLS_POLICY("good"))
    s3.put_bucket_versioning(Bucket="good", VersioningConfiguration={"Status": "Enabled"})
    boto3.client("s3", region_name="eu-west-1").create_bucket(
        Bucket="bad", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
    by_id = {r["resource_id"]: r for r in get_normalized_s3_resources()}
    assert (by_id["good"]["region"], by_id["good"]["tls_enforced"], by_id["good"]["versioning_enabled"]) == ("ap-south-1", True, True)
    assert (by_id["bad"]["region"], by_id["bad"]["tls_enforced"], by_id["bad"]["versioning_enabled"]) == ("eu-west-1", False, False)


def test_account_collector_reports_log_retention_and_guardduty(aws):
    from lambdas.rule_engine.handler import get_normalized_cloudtrail_resources
    logs = boto3.client("logs", region_name="ap-south-1")
    logs.create_log_group(logGroupName="short")
    logs.put_retention_policy(logGroupName="short", retentionInDays=30)
    logs.create_log_group(logGroupName="forever")
    report = {}
    resource = get_normalized_cloudtrail_resources(report)[0]
    assert resource["short_retention_log_groups"] == [{"name": "short", "days": 30}]
    assert resource["guardduty_enabled"] is False
    boto3.client("guardduty", region_name="ap-south-1").create_detector(Enable=True)
    assert get_normalized_cloudtrail_resources({})[0]["guardduty_enabled"] is True


# ---- measured accuracy on a labelled corpus (rules are deterministic, so this must be exact) ----
def _corpus(seed=7, n=200):
    rng = random.Random(seed)
    items = []
    for i in range(n):
        region = rng.choice(["ap-south-1", "ap-south-2", "us-east-1", "eu-west-1"])
        tls, ver = rng.random() < 0.6, rng.random() < 0.5
        res = bucket(resource_id=f"b{i}", region=region, tls_enforced=tls, versioning_enabled=ver,
                     encrypted=True, is_public=False)
        truth = {"data_residency_india": region not in ("ap-south-1", "ap-south-2"),
                 "tls_enforcement": not tls, "s3_versioning": not ver}
        items.append((res, truth))
    return items


def test_precision_and_recall_are_perfect_on_labelled_corpus(monkeypatch):
    monkeypatch.setenv("POLICYGUARD_PROFILE", "india")
    tp = fp = fn = 0
    for resource, truth in _corpus():
        flagged = {v["rule"] for v in run_rule_engine([resource])}
        for rule, expected in truth.items():
            tp += expected and rule in flagged
            fp += (not expected) and rule in flagged
            fn += expected and rule not in flagged
    assert tp > 100                     # the corpus actually exercises violations
    assert fp == 0 and fn == 0, f"false positives={fp}, false negatives={fn}"
