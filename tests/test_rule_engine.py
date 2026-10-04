import json
import pytest
from lambdas.rule_engine.rules.s3_public_bucket import check as check_s3_public
from lambdas.rule_engine.framework_mapping import RULE_TO_CLAUSE
from lambdas.rule_engine.handler import run_rule_engine, lambda_handler


def test_s3_public_bucket_flagged():
    resource = {
        "resource_type": "object_storage",
        "provider": "aws",
        "resource_id": "my-public-bucket",
        "is_public": True,
        "encrypted": False,
        "permissions": [],
        "tags": {},
    }
    res = check_s3_public(resource)
    assert res["compliant"] is False
    assert res["rule"] == "public_storage"
    assert res["resource_id"] == "my-public-bucket"


def test_s3_public_bucket_compliant():
    resource = {
        "resource_type": "object_storage",
        "provider": "aws",
        "resource_id": "my-private-bucket",
        "is_public": False,
        "encrypted": True,
        "permissions": [],
        "tags": {},
    }
    res = check_s3_public(resource)
    assert res["compliant"] is True
    assert res["rule"] == "public_storage"
    assert res["resource_id"] == "my-private-bucket"


def test_s3_public_bucket_non_object_storage():
    resource = {
        "resource_type": "compute",
        "provider": "aws",
        "resource_id": "i-12345678",
        "is_public": True,
        "encrypted": False,
        "permissions": [],
        "tags": {},
    }
    res = check_s3_public(resource)
    assert res["compliant"] is True


def test_framework_mapping_clause():
    assert "public_storage" in RULE_TO_CLAUSE
    assert RULE_TO_CLAUSE["public_storage"].startswith("CIS AWS")


def test_run_rule_engine_detects_violation():
    resources = [
        {
            "resource_type": "object_storage",
            "provider": "aws",
            "resource_id": "public-bucket-123",
            "is_public": True,
            "encrypted": False,
            "permissions": [],
            "tags": {"handles_personal_data": "true"},
        },
        {
            "resource_type": "object_storage",
            "provider": "aws",
            "resource_id": "secure-bucket-456",
            "is_public": False,
            "encrypted": True,
            "permissions": [],
            "tags": {},
        },
    ]

    # public-bucket-123 is also unencrypted, so filter to the public_storage rule
    violations = [v for v in run_rule_engine(resources) if v["rule"] == "public_storage"]
    assert len(violations) == 1
    assert violations[0]["rule"] == "public_storage"
    assert violations[0]["resource_id"] == "public-bucket-123"
    assert violations[0]["tier"] == "PRIVACY"
    assert "DPDP" in violations[0]["clause"]
    assert violations[0]["compliant"] is False


def test_lambda_handler():
    event = {
        "resources": [
            {
                "resource_type": "object_storage",
                "provider": "aws",
                "resource_id": "public-bucket-789",
                "is_public": True,
                "encrypted": False,
                "permissions": [],
                "tags": {},
            }
        ]
    }
    response = lambda_handler(event, None)
    assert response["statusCode"] == 200
    body = [v for v in json.loads(response["body"]) if v["rule"] == "public_storage"]
    assert len(body) == 1
    assert body[0]["resource_id"] == "public-bucket-789"


from lambdas.rule_engine.rules.encryption_at_rest import check as check_encryption
from lambdas.rule_engine.rules.iam_wildcard_policy import check as check_wildcard
from lambdas.rule_engine.rules.mfa_required import check as check_mfa


def _resource(resource_type, resource_id, **extra):
    base = {"resource_type": resource_type, "provider": "aws", "resource_id": resource_id,
            "is_public": False, "encrypted": True, "permissions": [], "tags": {}}
    return {**base, **extra}


def test_encryption_at_rest_flagged():
    res = check_encryption(_resource("object_storage", "plain-bucket", encrypted=False))
    assert res == {"compliant": False, "rule": "encryption_at_rest", "resource_id": "plain-bucket"}


def test_encryption_at_rest_compliant():
    assert check_encryption(_resource("object_storage", "enc-bucket"))["compliant"] is True


def test_encryption_at_rest_ignores_non_storage():
    assert check_encryption(_resource("iam_user", "bob", encrypted=False))["compliant"] is True


def test_iam_wildcard_policy_flagged():
    stmts = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    res = check_wildcard(_resource("iam_policy", "arn:policy/Admin", permissions=stmts))
    assert res == {"compliant": False, "rule": "wildcard_permission", "resource_id": "arn:policy/Admin"}


def test_iam_wildcard_service_star_flagged():
    stmts = [{"Effect": "Allow", "Action": ["s3:*"], "Resource": ["*"]}]
    assert check_wildcard(_resource("iam_policy", "p", permissions=stmts))["compliant"] is False


def test_iam_wildcard_policy_compliant():
    stmts = [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
        {"Effect": "Deny", "Action": "*", "Resource": "*"},
    ]
    assert check_wildcard(_resource("iam_policy", "p", permissions=stmts))["compliant"] is True


def test_mfa_required_flagged():
    res = check_mfa(_resource("iam_user", "intern", has_console_access=True, mfa_enabled=False))
    assert res == {"compliant": False, "rule": "mfa_required", "resource_id": "intern"}


def test_mfa_required_compliant():
    assert check_mfa(_resource("iam_user", "a", has_console_access=True, mfa_enabled=True))["compliant"] is True
    assert check_mfa(_resource("iam_user", "svc", has_console_access=False, mfa_enabled=False))["compliant"] is True


def test_new_rules_have_clauses():
    for rule in ("encryption_at_rest", "wildcard_permission", "mfa_required", "open_admin_ports"):
        assert rule in RULE_TO_CLAUSE
    assert RULE_TO_CLAUSE["encryption_at_rest"].startswith("CIS AWS")


from lambdas.rule_engine.rules.open_admin_ports import check as check_open_admin_ports


def test_open_admin_ports_flagged():
    permissions = [{
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }]
    res = check_open_admin_ports(_resource("security_group", "sg-123", permissions=permissions))
    assert res == {"compliant": False, "rule": "open_admin_ports", "resource_id": "sg-123"}


def test_open_admin_ports_compliant():
    permissions = [{
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
    }]
    res = check_open_admin_ports(_resource("security_group", "sg-safe", permissions=permissions))
    assert res["compliant"] is True


def test_tier_classification_security_tier():
    resources = [{
        "resource_type": "object_storage",
        "provider": "aws",
        "resource_id": "sec-bucket",
        "is_public": True,
        "encrypted": False,
        "permissions": [],
        "tags": {"handles_personal_data": "false"},
    }]
    violations = [v for v in run_rule_engine(resources) if v["rule"] == "public_storage"]
    assert len(violations) == 1
    v = violations[0]
    assert v["tier"] == "SECURITY"
    assert v["clause"].startswith("CIS AWS")
    assert "DPDP" not in v["clause"]
    assert "GDPR" not in v["clause"]


def test_tier_classification_privacy_tier():
    resources = [{
        "resource_type": "object_storage",
        "provider": "aws",
        "resource_id": "priv-bucket",
        "is_public": True,
        "encrypted": False,
        "permissions": [],
        "tags": {"handles_personal_data": "true"},
    }]
    violations = [v for v in run_rule_engine(resources) if v["rule"] == "public_storage"]
    assert len(violations) == 1
    v = violations[0]
    assert v["tier"] == "PRIVACY"
    assert "DPDP" in v["clause"]


def test_tier_classification_no_tags_defaults_to_security():
    resources = [{
        "resource_type": "object_storage",
        "provider": "aws",
        "resource_id": "untagged-bucket",
        "is_public": True,
        "encrypted": False,
        "permissions": [],
        "tags": {},
    }]
    violations = [v for v in run_rule_engine(resources) if v["rule"] == "public_storage"]
    assert len(violations) == 1
    v = violations[0]
    assert v["tier"] == "SECURITY"
    assert v["clause"].startswith("CIS AWS")
