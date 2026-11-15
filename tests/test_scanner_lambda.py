"""Scheduled scanner: packaging is self-contained, and one invocation scans, stores, alerts and emits metrics."""
import json
import os
import subprocess
import sys
import zipfile

import pytest

moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_scanner_zip_imports_without_flask(tmp_path, monkeypatch):
    sys.path.insert(0, os.path.join(ROOT, "infra"))
    import package
    monkeypatch.setattr(package, "BUILD", str(tmp_path / "build"))
    scanner_zip = package.build("scanner.zip", package.COMMON + package.SCANNER_EXTRA)
    package.build("app.zip", package.COMMON + package.APP_EXTRA)

    unpacked = tmp_path / "unpacked"
    with zipfile.ZipFile(scanner_zip) as archive:
        archive.extractall(unpacked)
        names = archive.namelist()
    assert "lambdas/scanner/handler.py" in names and "db/dynamo_store.py" in names
    assert "compliance/india_catalog.json" in names
    assert not any(n.endswith(".pyc") or n.endswith(".db") for n in names)
    assert not any(n.startswith("dashboard/templates") for n in names)

    # Import in a clean interpreter where Flask is unavailable, as it would be in Lambda.
    code = ("import sys; sys.modules['flask'] = None; sys.path.insert(0, sys.argv[1]); "
            "import lambdas.scanner.handler as h; assert callable(h.lambda_handler)")
    result = subprocess.run([sys.executable, "-I", "-c", code, str(unpacked)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.fixture
def aws(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "ap-south-1",
                       "POLICYGUARD_BACKEND": "dynamodb", "POLICYGUARD_PROFILE": "india"}.items():
        monkeypatch.setenv(key, value)
    with moto.mock_aws():
        from db.dynamo_store import DynamoStore
        DynamoStore(create=True)
        yield


def test_handler_scans_stores_and_alerts_on_new_high_findings(aws, monkeypatch, capsys):
    sns = boto3.client("sns")
    topic = sns.create_topic(Name="alerts")["TopicArn"]
    queue = boto3.client("sqs")
    queue_url = queue.create_queue(QueueName="capture")["QueueUrl"]
    queue_arn = queue.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)
    monkeypatch.setenv("POLICYGUARD_ALERT_TOPIC_ARN", topic)

    # A public bucket is a HIGH finding.
    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(Bucket="leaky", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    s3.put_bucket_policy(Bucket="leaky", Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::leaky/*"}]}))

    from lambdas.scanner.handler import lambda_handler
    result = lambda_handler({}, None)
    assert result["status"] in ("COMPLETED", "PARTIAL") and result["violations"] >= 1

    from db.store import connect, get_audit_log, get_findings
    conn = connect()
    assert any(f["rule"] == "public_storage" and f["resource_id"] == "leaky" for f in get_findings(conn))
    assert get_audit_log(conn)

    messages = queue.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10).get("Messages", [])
    assert messages and "HIGH" in messages[0]["Body"]

    metric_lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith('{"_aws"')]
    assert metric_lines and metric_lines[0]["HighFindings"] >= 1 and metric_lines[0]["ScanFailed"] == 0

    capsys.readouterr()
    lambda_handler({}, None)            # same finding again: no second alert
    again = queue.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10).get("Messages", [])
    assert not again
