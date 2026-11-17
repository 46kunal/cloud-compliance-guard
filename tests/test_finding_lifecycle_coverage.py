import json
import re
import sqlite3
from pathlib import Path
from unittest.mock import patch

from botocore.exceptions import ClientError

from dashboard import scanner
from dashboard.routes.compliance_score import compute_score
from db.schema import begin_scan, connect, get_finding_events, get_findings, get_latest_scan, get_violations, save_scan
from lambdas.audit_logger.hash_chain import verify_chain
from lambdas.audit_logger.handler import build_audit_log
from lambdas.rule_engine.handler import get_normalized_s3_resources, run_rule_engine


def _open_sg():
    return {"resource_type": "security_group", "provider": "aws", "resource_id": "sg-123",
            "permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], "tags": {}}


def _public_bucket():
    return {"resource_type": "object_storage", "provider": "aws", "resource_id": "policyguard-history-bucket",
            "is_public": True, "encrypted": True, "permissions": [], "tags": {}}


def _healthy_report():
    return {name: {"status": "SUCCESS", "errors": []} for name in scanner.SERVICES}


def _setup_scanner(monkeypatch):
    monkeypatch.setattr(scanner, "_account_scope", lambda: "123456789012")
    monkeypatch.setattr(scanner, "_region_scope", lambda: "ap-south-1")
    monkeypatch.setattr(scanner, "remediate_violations", lambda findings: [])


def test_finding_created_persisted_and_transitions_to_active(tmp_path, monkeypatch):
    _setup_scanner(monkeypatch)
    conn = connect(str(tmp_path / "lifecycle.db"))
    first = scanner.scan_and_save(conn, [_open_sg()])
    finding, = get_violations(conn)
    original_first_detected = finding["first_detected"]
    assert first["status"] == "COMPLETED"
    assert finding["status"] == "NEW"
    assert finding["first_detected"] == finding["last_detected"]

    second = scanner.scan_and_save(conn, [_open_sg()])
    finding, = get_violations(conn)
    assert second["new"] == 0
    assert finding["status"] == "ACTIVE"
    assert finding["first_detected"] == original_first_detected
    assert finding["last_detected"] >= original_first_detected
    assert [event["event_type"] for event in get_finding_events(conn)] == ["CONFIRMED", "DETECTED"]
    conn.close()


def test_finding_resolves_only_after_successful_scope_and_reopens(tmp_path, monkeypatch):
    _setup_scanner(monkeypatch)
    conn = connect(str(tmp_path / "reopen.db"))
    scanner.scan_and_save(conn, [_open_sg()])
    resolved_scan = scanner.scan_and_save(conn, [])
    finding = get_findings(conn)[0]
    assert resolved_scan["resolved"] == 1
    assert finding["status"] == "RESOLVED"

    reopened = scanner.scan_and_save(conn, [_open_sg()])
    finding = get_findings(conn)[0]
    assert reopened["new"] == 1
    assert finding["status"] == "REOPENED"
    assert len(get_findings(conn)) == 1
    assert [event["event_type"] for event in get_finding_events(conn)] == ["REOPENED", "RESOLVED", "DETECTED"]
    conn.close()


def test_partial_and_failed_scans_do_not_resolve_findings(tmp_path, monkeypatch):
    _setup_scanner(monkeypatch)
    conn = connect(str(tmp_path / "coverage.db"))
    scanner.scan_and_save(conn, [_public_bucket()])

    partial = _healthy_report()
    partial["s3"] = {"status": "FAILED", "errors": ["AccessDenied"]}
    result = scanner.scan_and_save(conn, [], collection_report=partial)
    assert result["status"] == "PARTIAL"
    assert result["resolved"] == 0
    assert get_violations(conn)[0]["status"] == "NEW"
    from dashboard.app import create_app
    import dashboard.routes.compliance_score as score_route
    monkeypatch.setattr(score_route, "connect", lambda: connect(str(tmp_path / "coverage.db")))
    partial_response = create_app().test_client().get("/api/compliance-score")
    assert partial_response.status_code == 200
    partial_scan_json = partial_response.get_json()["scan"]
    assert partial_scan_json["status"] == "PARTIAL"
    assert partial_scan_json["service_statuses"]["s3"]["status"] == "FAILED"
    assert partial_scan_json["collection_errors"][0]["service"] == "s3"

    failed = {name: {"status": "FAILED", "errors": ["credentials unavailable"]} for name in scanner.SERVICES}
    result = scanner.scan_and_save(conn, [], collection_report=failed)
    assert result["status"] == "FAILED"
    assert result["resolved"] == 0
    assert get_violations(conn)[0]["status"] == "NEW"
    assert get_latest_scan(conn)["collection_errors"]
    response = create_app().test_client().get("/api/compliance-score")
    assert response.status_code == 200
    scan_json = response.get_json()["scan"]
    assert scan_json["status"] == "FAILED"
    assert all(isinstance(item["service"], str) and isinstance(item["message"], str)
               for item in scan_json["collection_errors"])
    conn.close()


def test_permission_denied_collector_is_partial_not_clean():
    report = {"s3": {"status": "NOT_SCANNED", "errors": []}}
    client = type("S3", (), {})()
    client.list_buckets = lambda: {"Buckets": [{"Name": "bucket-one"}]}
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetBucketEncryption")
    client.get_bucket_policy_status = lambda **kwargs: {"PolicyStatus": {"IsPublic": False}}
    client.get_bucket_policy = lambda **kwargs: (_ for _ in ()).throw(ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy", "Message": "none"}}, "GetBucketPolicy"))
    client.get_public_access_block = lambda **kwargs: {"PublicAccessBlockConfiguration": {}}
    client.get_bucket_encryption = lambda **kwargs: (_ for _ in ()).throw(denied)
    client.get_bucket_tagging = lambda **kwargs: (_ for _ in ()).throw(ClientError(
        {"Error": {"Code": "NoSuchTagSet", "Message": "none"}}, "GetBucketTagging"))
    with patch("lambdas.rule_engine.handler.boto3.client", return_value=client):
        resources = get_normalized_s3_resources(report)
    assert len(resources) == 1
    assert report["s3"]["status"] == "PARTIAL"
    assert "AccessDenied" in report["s3"]["errors"][0]
    assert run_rule_engine(resources) == []


def test_score_is_not_assessed_without_assessed_resources():
    assert compute_score([], 0) is None
    assert compute_score([], 4) == 100
    assert compute_score([{"resource_id": "r1"}], 4) == 75


def test_legacy_scan_migration_preserves_rows_and_marks_coverage_unknown(tmp_path, monkeypatch):
    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT DEFAULT CURRENT_TIMESTAMP, resources_scanned INTEGER NOT NULL);
        CREATE TABLE violations (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, resource_id TEXT NOT NULL, clause TEXT, severity TEXT, remediation TEXT, detected_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE audit_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, details TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
    """)
    conn.execute("INSERT INTO scans(resources_scanned) VALUES (3)")
    conn.execute("INSERT INTO violations(rule,resource_id,clause,severity,remediation) VALUES (?,?,?,?,?)",
                 ("public_storage", "old-bucket", "legacy clause", "HIGH", json.dumps({})))
    conn.commit()
    conn.close()

    migrated = connect(path)
    finding, = get_findings(migrated)
    scan = get_latest_scan(migrated)
    assert finding["resource_id"] == "old-bucket"
    assert finding["status"] == "ACTIVE"
    assert scan["status"] == "PARTIAL"
    assert scan["resources_assessed"] == 0
    assert scan["resources_discovered"] == 3
    assert scan["services_scanned"] == [] and scan["service_statuses"] == {}
    assert scan["collection_errors"] == [{
        "service": "scan", "message": "Coverage metadata was unavailable in this legacy scan"
    }]
    assert migrated.execute("SELECT COUNT(*) FROM violations").fetchone()[0] == 1

    import dashboard.routes.compliance_score as score_route
    monkeypatch.setattr(score_route, "connect", lambda: connect(path))
    from dashboard.app import create_app
    legacy_response = create_app().test_client().get("/api/compliance-score")
    assert legacy_response.status_code == 200
    legacy_scan = legacy_response.get_json()["scan"]
    assert legacy_scan["status"] == "PARTIAL"
    assert legacy_scan["collection_errors"][0]["service"] == "scan"

    # Model rows already migrated by the prior release, which stored the note as a bare string.
    migrated.execute("UPDATE scans SET collection_errors=?", (json.dumps(["Coverage metadata was unavailable in this legacy scan"]),))
    migrated.commit()
    prior_release_response = create_app().test_client().get("/api/compliance-score")
    assert prior_release_response.status_code == 200
    prior_release_error = prior_release_response.get_json()["scan"]["collection_errors"][0]
    assert prior_release_error == {
        "service": "scan", "message": "Coverage metadata was unavailable in this legacy scan"
    }
    migrated.close()


def test_existing_audit_chain_still_verifies():
    chain = build_audit_log([{"rule": "public_storage", "resource_id": "bucket"}])
    assert verify_chain(chain)


def test_dashboard_routes_render_and_report_not_assessed(tmp_path, monkeypatch):
    from dashboard.app import create_app
    import dashboard.routes.audit_log as audit_route
    import dashboard.routes.compliance_score as score_route
    import dashboard.routes.violations as findings_route
    import dashboard.scanner as scanner_module
    import db.schema as db_schema

    database = str(tmp_path / "dashboard.db")
    connection_factory = lambda: connect(database)
    monkeypatch.setattr(score_route, "connect", connection_factory)
    monkeypatch.setattr(findings_route, "connect", connection_factory)
    monkeypatch.setattr(audit_route, "connect", connection_factory)
    monkeypatch.setattr(db_schema, "connect", connection_factory)
    monkeypatch.setattr(scanner_module, "scan_and_save", lambda conn: {"scan_id": 1, "status": "COMPLETED"})
    app = create_app()
    client = app.test_client()

    js_dir = Path(__file__).parents[1] / "dashboard" / "static" / "js"
    javascript = "\n".join(p.read_text(encoding="utf-8") for p in sorted(js_dir.glob("*.js")))
    frontend_urls = set(re.findall(r'(?:getJson|postJson|fetch)\("(/api/[^"?]+)', javascript))
    assert frontend_urls == {"/api/compliance-score", "/api/findings", "/api/audit-log", "/api/scan", "/api/findings/",
                             "/api/scans", "/api/frameworks", "/api/usage", "/api/instance", "/api/me",
                             "/api/reports/saved", "/api/account", "/api/audit-anchors",
                             "/api/monitored-accounts", "/api/monitored-accounts/", "/api/view", "/api/users",
                             "/api/controls", "/api/incidents", "/api/incidents/"}
    registered = {(rule.rule, method) for rule in app.url_map.iter_rules() for method in rule.methods}
    for api_url in ("/api/compliance-score", "/api/findings", "/api/audit-log"):
        assert (api_url, "GET") in registered
    assert ("/api/findings/<finding_id>/evidence", "GET") in registered
    assert ("/api/scan", "POST") in registered
    assert ("/api/violations", "GET") in registered

    page = client.get("/")
    audit_page = client.get("/audit")
    score = client.get("/api/compliance-score").get_json()
    findings = client.get("/api/findings").get_json()
    violations = client.get("/api/violations").get_json()
    audit = client.get("/api/audit-log").get_json()
    scan_response = client.post("/api/scan")
    assert page.status_code == 200 and b"Configuration compliance" in page.data
    assert audit_page.status_code == 200
    assert score["score"] is None and score["score_label"] == "Not Assessed"
    assert score["resources_assessed"] == score["resources_discovered"] == 0
    assert score["total_violations"] == 0 and score["by_severity"] == {}
    assert score["last_scan"] is None
    assert findings == []
    assert violations == []
    assert audit == {"chain_valid": True, "entries": []}
    assert scan_response.status_code == 200 and scan_response.get_json()["status"] == "COMPLETED"


def test_findings_api_returns_persisted_findings_and_compliance_metrics(tmp_path, monkeypatch):
    from dashboard.app import create_app
    import dashboard.routes.compliance_score as score_route
    import dashboard.routes.violations as findings_route

    database = str(tmp_path / "findings-api.db")
    connection_factory = lambda: connect(database)
    monkeypatch.setattr(score_route, "connect", connection_factory)
    monkeypatch.setattr(findings_route, "connect", connection_factory)
    conn = connection_factory()
    started_at = "2026-11-13T00:00:00+00:00"
    scan_id = begin_scan(conn, started_at, "123456789012", "ap-south-1")
    finding = {"rule": "public_storage", "provider": "aws", "account_scope": "123456789012",
               "resource_type": "object_storage", "resource_id": "bucket-public", "clause": "test control",
               "severity": "HIGH", "compliant": False}
    resources = [
        {"resource_type": "object_storage", "resource_id": "bucket-public"},
        {"resource_type": "object_storage", "resource_id": "bucket-private"},
    ]
    save_scan(conn, 2, [finding], [], [], scan_id=scan_id, started_at=started_at,
              status="COMPLETED", account_scope="123456789012", region_scope="ap-south-1",
              resources_assessed=2, services_scanned=["s3"],
              service_statuses={"s3": {"status": "SUCCESS", "errors": []}},
              assessed_resource_records=resources)
    conn.execute("UPDATE scans SET status='completed',service_statuses=? WHERE id=?",
                 (json.dumps({"s3": {"status": "success", "errors": []}}), scan_id))
    conn.commit()
    conn.close()

    client = create_app().test_client()
    response = client.get("/api/findings")
    assert response.status_code == 200
    findings = response.get_json()
    assert len(findings) == 1
    assert findings[0]["rule"] == "public_storage"
    assert findings[0]["resource_id"] == "bucket-public"
    assert findings[0]["status"] == "NEW"
    assert findings[0]["first_detected"] and findings[0]["last_detected"]
    assert findings[0]["remediation"] == {}
    assert findings[0]["evidence_available"] is False

    score_response = client.get("/api/compliance-score")
    assert score_response.status_code == 200
    score = score_response.get_json()
    assert score["score"] == 50
    assert score["resources_assessed"] == 2 and score["resources_discovered"] == 2
    assert score["total_violations"] == 1 and score["by_severity"] == {"HIGH": 1}
    assert score["last_scan"] is not None
    assert score["scan"]["status"] == "COMPLETED"
    assert score["scan"]["service_statuses"]["s3"]["status"] == "SUCCESS"
