"""infra/demo_resources.py: no silent failures on create, full prefix sweep on delete (moto, no real AWS)."""
import importlib.util
import os
from unittest.mock import MagicMock

import pytest

moto = pytest.importorskip("moto")
import boto3

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "infra", "demo_resources.py")


@pytest.fixture
def demo(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    spec = importlib.util.spec_from_file_location("demo_resources", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with moto.mock_aws():
        yield module


def _bucket_names():
    return {b["Name"] for b in boto3.client("s3").list_buckets()["Buckets"]}


def test_step_treats_already_exists_as_success_but_reports_other_errors(demo, capsys):
    failures = []
    assert demo._step(failures, "thing", MagicMock(side_effect=RuntimeError("EntityAlreadyExists"))) is True
    assert demo._step(failures, "other", MagicMock(side_effect=RuntimeError("AccessDenied"))) is False
    assert failures == ["other"]
    assert "FAILED other" in capsys.readouterr().out


def test_create_creates_everything_and_is_rerunnable(demo):
    demo.create()
    demo.create()  # second run: "already exists" must not be an error
    iam = boto3.client("iam")
    assert iam.get_user(UserName=demo.USER_NAME)["User"]["UserName"] == demo.USER_NAME
    assert {p["PolicyName"] for p in iam.list_policies(Scope="Local")["Policies"]} == {
        demo.POLICY_NAME, demo.READONLY_POLICY_NAME}
    assert len([n for n in _bucket_names() if n.startswith("policyguard-demo-")]) == 2


def test_create_exits_nonzero_when_an_iam_step_fails(demo, monkeypatch, capsys):
    real_client = boto3.client

    def client_with_denied_create_user(name, *args, **kwargs):
        client = real_client(name, *args, **kwargs)
        if name == "iam":
            client.create_user = MagicMock(side_effect=RuntimeError("AccessDenied: iam:TagUser"))
        return client

    monkeypatch.setattr(demo.boto3, "client", client_with_denied_create_user)
    with pytest.raises(SystemExit) as exit_info:
        demo.create()
    out = capsys.readouterr().out
    assert exit_info.value.code == 1
    assert "FAILED IAM user" in out and "INCOMPLETE" in out
    assert "IAM user without MFA" not in out  # must not claim success


def test_delete_sweeps_all_demo_buckets_including_leftovers_but_not_others(demo):
    demo.create()
    s3 = boto3.client("s3")
    for name in ("policyguard-demo-user-pub-unenc-123", "unrelated-bucket"):
        s3.create_bucket(Bucket=name)
        s3.put_object(Bucket=name, Key="data.txt", Body=b"x")  # non-empty: delete must empty it first

    demo.delete()

    assert _bucket_names() == {"unrelated-bucket"}
    iam = boto3.client("iam")
    assert iam.list_policies(Scope="Local")["Policies"] == []
    assert iam.list_users()["Users"] == []
