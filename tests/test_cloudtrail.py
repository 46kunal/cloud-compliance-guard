"""CloudTrail rule + collector, and the remediation/scanner encryption consistency regression."""
import json
from unittest.mock import patch

import pytest

from lambdas.remediation.actions import enforce_encryption
from lambdas.remediation.safety import dry_run
from lambdas.risk_classifier.severity_rules import classify
from lambdas.rule_engine.framework_mapping import PRIVACY_CLAUSE_MAP, SECURITY_CONTROL_MAP
from lambdas.rule_engine.handler import (
    get_normalized_cloudtrail_resources,
    get_normalized_s3_resources,
    run_rule_engine,
)
from lambdas.rule_engine.rules.cloudtrail_enabled import check

moto = pytest.importorskip("moto")
import boto3


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        yield


def _config(active: bool) -> dict:
    return {"resource_type": "cloudtrail_config", "resource_id": "cloudtrail:account-wide",
            "tags": {}, "active_multi_region_trail": active}


def _make_trail(name: str, multi_region: bool, logging: bool) -> None:
    boto3.client("s3").create_bucket(Bucket=f"{name}-logs")
    ct = boto3.client("cloudtrail")
    ct.create_trail(Name=name, S3BucketName=f"{name}-logs", IsMultiRegionTrail=multi_region)
    if logging:
        ct.start_logging(Name=name)


# ---- rule ------------------------------------------------------------------

def test_rule_flags_account_without_active_multi_region_trail():
    assert check(_config(False)) == {"compliant": False, "rule": "cloudtrail_enabled",
                                     "resource_id": "cloudtrail:account-wide"}


def test_rule_passes_with_active_multi_region_trail():
    assert check(_config(True))["compliant"] is True


def test_rule_ignores_other_resource_types():
    assert check({"resource_type": "object_storage", "resource_id": "b"})["compliant"] is True


def test_rule_has_both_tier_clauses_and_medium_severity():
    assert "Audit Logging" in PRIVACY_CLAUSE_MAP["cloudtrail_enabled"]
    assert SECURITY_CONTROL_MAP["cloudtrail_enabled"].startswith("CIS AWS Foundations Benchmark 3.1")
    assert classify({"rule": "cloudtrail_enabled"}) == "MEDIUM"


def test_violation_is_security_tier_with_cis_clause():
    (violation,) = [v for v in run_rule_engine([_config(False)]) if v["rule"] == "cloudtrail_enabled"]
    assert violation["tier"] == "SECURITY"
    assert violation["clause"] == SECURITY_CONTROL_MAP["cloudtrail_enabled"]


# ---- collector -------------------------------------------------------------

def test_collector_reports_no_trail(aws):
    (resource,) = get_normalized_cloudtrail_resources()
    assert resource["trail_count"] == 0 and resource["active_multi_region_trail"] is False


def test_collector_accepts_logging_multi_region_trail(aws):
    _make_trail("org-trail", multi_region=True, logging=True)
    (resource,) = get_normalized_cloudtrail_resources()
    assert resource["active_multi_region_trail"] is True


@pytest.mark.parametrize("multi_region,logging", [(True, False), (False, True)])
def test_collector_rejects_stopped_or_single_region_trail(aws, multi_region, logging):
    _make_trail("weak-trail", multi_region=multi_region, logging=logging)
    (resource,) = get_normalized_cloudtrail_resources()
    assert resource["trail_count"] == 1 and resource["active_multi_region_trail"] is False


def test_collector_api_error_is_not_reported_as_missing_trail(aws, capsys):
    with patch("lambdas.rule_engine.handler.boto3.client", side_effect=RuntimeError("AccessDenied")):
        assert get_normalized_cloudtrail_resources() == []
    assert "CloudTrail scan failed" in capsys.readouterr().err


# ---- regression: remediation must actually clear the scanner's finding ------

def test_enforce_encryption_fix_satisfies_the_scanner(aws, tmp_path, monkeypatch):
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text(json.dumps({"allowed_resource_ids": ["fixme-bucket"]}))
    monkeypatch.setattr(dry_run, "ALLOWLIST_PATH", str(allowlist))
    boto3.client("s3").create_bucket(Bucket="fixme-bucket")

    def encryption_findings():
        return [v for v in run_rule_engine(get_normalized_s3_resources()) if v["rule"] == "encryption_at_rest"]

    assert len(encryption_findings()) == 1
    assert enforce_encryption.remediate("fixme-bucket", dry_run=False)["success"] is True
    assert encryption_findings() == []
