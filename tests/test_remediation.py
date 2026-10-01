import json
from unittest.mock import MagicMock, patch

import pytest

from lambdas.remediation.actions import close_public_bucket, enforce_encryption, revoke_iam_permission
from lambdas.remediation.handler import remediate_violations
from lambdas.remediation.safety import dry_run

ACTIONS = [
    (close_public_bucket, "put_public_access_block"),
    (enforce_encryption, "put_bucket_encryption"),
]


@pytest.fixture
def allowlist(tmp_path, monkeypatch):
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps({"allowed_resource_ids": ["allowed-bucket", "arn:policy/Admin"]}))
    monkeypatch.setattr(dry_run, "ALLOWLIST_PATH", str(path))


def test_dry_run_default_is_true():
    assert dry_run.DRY_RUN is True


@pytest.mark.parametrize("module,method", ACTIONS)
def test_dry_run_never_mutates(module, method, allowlist):
    with patch("boto3.client") as client:
        result = module.remediate("allowed-bucket", dry_run=True)
    client.assert_not_called()
    assert result["dry_run"] is True and result["success"] is True


@pytest.mark.parametrize("module,method", ACTIONS)
def test_not_allowlisted_never_mutates(module, method, allowlist):
    with patch("boto3.client") as client:
        result = module.remediate("random-bucket", dry_run=False)
    client.assert_not_called()
    assert result["success"] is False


@pytest.mark.parametrize("module,method", ACTIONS)
def test_allowlisted_live_calls_mutation(module, method, allowlist):
    with patch("boto3.client") as client:
        result = module.remediate("allowed-bucket", dry_run=False)
    getattr(client.return_value, method).assert_called_once()
    assert result["success"] is True and result["dry_run"] is False


def test_revoke_iam_dry_run_never_mutates(allowlist):
    with patch("boto3.client") as client:
        revoke_iam_permission.remediate("arn:policy/Admin", dry_run=True)
    client.assert_not_called()


def test_revoke_iam_live_detaches(allowlist):
    iam = MagicMock()
    iam.get_paginator.return_value.paginate.return_value = [
        {"PolicyUsers": [{"UserName": "bob"}], "PolicyGroups": [], "PolicyRoles": [{"RoleName": "r1"}]}
    ]
    with patch("boto3.client", return_value=iam):
        result = revoke_iam_permission.remediate("arn:policy/Admin", dry_run=False)
    iam.detach_user_policy.assert_called_once_with(UserName="bob", PolicyArn="arn:policy/Admin")
    iam.detach_role_policy.assert_called_once_with(RoleName="r1", PolicyArn="arn:policy/Admin")
    assert result["detached"] == ["user/bob", "role/r1"]


def test_missing_allowlist_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(dry_run, "ALLOWLIST_PATH", str(tmp_path / "nope.json"))
    assert dry_run.is_remediation_allowed("anything") is False


def test_handler_dispatches_and_skips_manual(allowlist):
    classified = [
        {"rule": "public_storage", "resource_id": "b1", "severity": "HIGH"},
        {"rule": "mfa_required", "resource_id": "bob", "severity": "MEDIUM"},
    ]
    with patch("boto3.client") as client:
        results = remediate_violations(classified, dry_run=True)
    client.assert_not_called()
    assert results[0]["action"] == "close_public_bucket"
    assert results[1]["action"] == "manual_review"
