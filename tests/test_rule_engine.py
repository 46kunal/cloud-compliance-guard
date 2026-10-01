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
    assert RULE_TO_CLAUSE["public_storage"] == "GDPR Article 32 — Security of Processing"


def test_run_rule_engine_detects_violation():
    resources = [
        {
            "resource_type": "object_storage",
            "provider": "aws",
            "resource_id": "public-bucket-123",
            "is_public": True,
            "encrypted": False,
            "permissions": [],
            "tags": {},
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

    violations = run_rule_engine(resources)
    assert len(violations) == 1
    assert violations[0]["rule"] == "public_storage"
    assert violations[0]["resource_id"] == "public-bucket-123"
    assert violations[0]["clause"] == "GDPR Article 32 — Security of Processing"
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
    body = json.loads(response["body"])
    assert len(body) == 1
    assert body[0]["resource_id"] == "public-bucket-789"
