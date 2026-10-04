import json
import pytest
from lambdas.risk_classifier.severity_rules import classify
from lambdas.risk_classifier.handler import classify_violations, lambda_handler


def test_classify_high_severity():
    assert classify({"rule": "public_storage"}) == "HIGH"
    assert classify({"rule": "wildcard_permission"}) == "HIGH"


def test_classify_medium_severity():
    assert classify({"rule": "encryption_at_rest"}) == "MEDIUM"
    assert classify({"rule": "mfa_required"}) == "MEDIUM"


def test_classify_low_severity():
    assert classify({"rule": "other_rule"}) == "LOW"
    assert classify({}) == "LOW"


def test_classify_violations():
    violations = [
        {"rule": "public_storage", "resource_id": "bucket-1", "clause": "DPDP Act 2023 Sec. 8(5)"},
        {"rule": "encryption_at_rest", "resource_id": "bucket-2", "clause": "CIS AWS Foundations Benchmark"},
        {"rule": "unknown_rule", "resource_id": "res-3", "clause": "N/A"},
    ]
    classified = classify_violations(violations)
    assert len(classified) == 3
    assert classified[0]["severity"] == "HIGH"
    assert classified[1]["severity"] == "MEDIUM"
    assert classified[2]["severity"] == "LOW"


def test_lambda_handler():
    event = {
        "violations": [
            {"rule": "public_storage", "resource_id": "bucket-pub", "clause": "DPDP Act 2023 Sec. 8(5)"}
        ]
    }
    res = lambda_handler(event, None)
    assert res["statusCode"] == 200
    body = json.loads(res["body"])
    assert len(body) == 1
    assert body[0]["severity"] == "HIGH"
