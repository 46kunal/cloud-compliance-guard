import json

from dashboard import scanner
from dashboard.app import create_app
from db.schema import connect, get_findings, get_finding_evidence
from dashboard.evidence import canonical_evidence
from dashboard.evidence import build_evidence_records
from lambdas.rule_engine.handler import run_rule_engine


def _public_bucket(resource_id, **extra):
    return {"resource_type": "object_storage", "provider": "aws", "resource_id": resource_id,
            "is_public": True, "encrypted": True, "permissions": [], "tags": {}, **extra}


def _setup(monkeypatch, path):
    monkeypatch.setattr(scanner, "_account_scope", lambda: "111122223333")
    monkeypatch.setattr(scanner, "_region_scope", lambda: "ap-south-1")
    monkeypatch.setattr(scanner, "remediate_violations", lambda _findings: [])
    import dashboard.routes.violations as route
    monkeypatch.setattr(route, "connect", lambda: connect(str(path)))


def test_evidence_generated_persisted_and_returned_for_exact_finding(tmp_path, monkeypatch):
    path = tmp_path / "evidence.db"
    _setup(monkeypatch, path)
    conn = connect(str(path))
    first_scan = scanner.scan_and_save(conn, [_public_bucket("bucket-one")])
    finding, = get_findings(conn)
    records = get_finding_evidence(conn, finding["id"])
    assert len(records) == 1
    evidence = records[0]
    assert evidence["finding_id"] == finding["id"]
    assert evidence["scan_id"] == first_scan["scan_id"]
    assert evidence["scan_status"] == "COMPLETED"
    assert evidence["detected_at"] and evidence["collection_status"] == "COLLECTED"
    assert evidence["resource_id"] == "bucket-one"
    assert evidence["resource_type"] == "object_storage" and evidence["service"] == "s3"
    assert evidence["observed_configuration"] == {"is_public": True}
    assert evidence["expected_condition"] is False
    assert evidence["rule_reference"] == "public_storage"
    assert evidence["compliance_mapping"] == finding["clause"]
    assert evidence["recommended_action"]
    assert evidence["lifecycle_status"] == finding["status"]
    payload = dict(evidence)
    digest = payload.pop("evidence_sha256")
    payload.pop("evidence_id")
    assert canonical_evidence(payload)[1] == digest

    response = create_app().test_client().get(f"/api/findings/{finding['id']}/evidence")
    assert response.status_code == 200
    assert response.get_json() == {"finding_id": finding["id"], "evidence": records}
    findings_response = create_app().test_client().get("/api/findings")
    assert findings_response.status_code == 200
    assert findings_response.get_json()[0]["evidence_available"] is True
    conn.close()


def test_evidence_history_survives_later_scan_and_isolated_by_finding(tmp_path, monkeypatch):
    path = tmp_path / "history.db"
    _setup(monkeypatch, path)
    conn = connect(str(path))
    scanner.scan_and_save(conn, [_public_bucket("bucket-one"), _public_bucket("bucket-two")])
    findings = {item["resource_id"]: item for item in get_findings(conn)}
    scanner.scan_and_save(conn, [_public_bucket("bucket-one"), _public_bucket("bucket-two")])
    first_records = get_finding_evidence(conn, findings["bucket-one"]["id"])
    second_records = get_finding_evidence(conn, findings["bucket-two"]["id"])
    assert len(first_records) == len(second_records) == 2
    assert all(item["resource_id"] == "bucket-one" for item in first_records)
    assert all(item["resource_id"] == "bucket-two" for item in second_records)
    client = create_app().test_client()
    result = client.get(f"/api/findings/{findings['bucket-one']['id']}/evidence").get_json()
    assert {item["resource_id"] for item in result["evidence"]} == {"bucket-one"}
    conn.close()


def test_evidence_api_handles_invalid_missing_and_legacy_findings(tmp_path, monkeypatch):
    path = tmp_path / "missing.db"
    _setup(monkeypatch, path)
    conn = connect(str(path))
    finding = {"rule": "public_storage", "provider": "aws", "account_scope": "legacy",
               "resource_type": "object_storage", "resource_id": "old-bucket", "clause": None,
               "severity": "HIGH", "compliant": False}
    conn.execute("INSERT INTO findings(finding_key,rule,provider,account_scope,resource_type,resource_id,clause,severity,status,first_detected,last_detected) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                 ("legacy-test-key", finding["rule"], finding["provider"], finding["account_scope"],
                  finding["resource_type"], finding["resource_id"], None, "HIGH", "ACTIVE", "then", "then"))
    conn.commit()
    legacy_id = conn.execute("SELECT id FROM findings WHERE finding_key='legacy-test-key'").fetchone()[0]
    conn.close()
    client = create_app().test_client()
    assert client.get(f"/api/findings/{legacy_id}/evidence").get_json() == {
        "finding_id": legacy_id, "evidence": []
    }
    legacy_finding = next(item for item in client.get("/api/findings").get_json() if item["id"] == legacy_id)
    assert legacy_finding["evidence_available"] is False
    assert client.get("/api/findings/nope/evidence").status_code == 400
    assert client.get("/api/findings/99999/evidence").status_code == 404


def test_evidence_omits_secrets_and_marks_partial_metadata(tmp_path, monkeypatch):
    path = tmp_path / "sensitive.db"
    _setup(monkeypatch, path)
    resource = {"resource_type": "iam_policy", "provider": "aws", "resource_id": "policy-x",
                "permissions": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                                 "SecretAccessKey": "sensitive-value"}], "tags": {}}
    conn = connect(str(path))
    scanner.scan_and_save(conn, [resource])
    finding = next(item for item in get_findings(conn) if item["rule"] == "wildcard_permission")
    evidence, = get_finding_evidence(conn, finding["id"])
    assert evidence["collection_status"] == "COLLECTED"
    assert "sensitive-value" not in json.dumps(evidence)
    assert "[REDACTED]" in json.dumps(evidence)
    conn.execute("UPDATE finding_evidence SET evidence_json=? WHERE finding_id=?",
                 (json.dumps({"observed_configuration": {}}), finding["id"]))
    conn.commit()
    # A legacy-style evidence row with omitted optional fields remains readable.
    response = create_app().test_client().get(f"/api/findings/{finding['id']}/evidence")
    assert response.status_code == 200
    assert response.get_json()["evidence"][0]["observed_configuration"] == {}
    assert response.get_json()["evidence"][0]["evidence_id"]
    conn.close()


def test_evidence_uses_rule_observations_and_reports_unmapped_controls():
    resources = [
        {"resource_type": "iam_user", "provider": "aws", "resource_id": "user-mfa",
         "has_console_access": True, "mfa_enabled": False},
        {"resource_type": "security_group", "provider": "aws", "resource_id": "sg-admin",
         "permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                          "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
        {"resource_type": "cloudtrail_config", "provider": "aws", "resource_id": "account-cloudtrail",
         "active_multi_region_trail": False},
    ]
    classified = run_rule_engine(resources)
    evidence = build_evidence_records(classified, resources, 7, "2026-11-13T01:00:00Z", "123", "ap-south-1")
    by_rule = {item["rule"]: item["evidence"] for item in evidence}
    assert by_rule["mfa_required"]["observed_configuration"] == {
        "has_console_access": True, "mfa_enabled": False
    }
    assert by_rule["open_admin_ports"]["observed_configuration"]["matching_ingress_rules"]
    assert by_rule["cloudtrail_enabled"]["observed_configuration"] == {"active_multi_region_trail": False}
    assert all(item["detected_at"] == "2026-11-13T01:00:00Z" for item in by_rule.values())
    unmapped = build_evidence_records(
        [{**classified[0], "clause": "N/A"}], resources, 8, "then", "123", "ap-south-1"
    )
    assert unmapped[0]["evidence"]["compliance_mapping"] == "Not mapped"


def test_partial_scan_status_is_preserved_and_failed_service_evidence_is_not_saved(tmp_path, monkeypatch):
    path = tmp_path / "coverage.db"
    _setup(monkeypatch, path)
    conn = connect(str(path))
    report = {name: {"status": "SUCCESS", "errors": []} for name in scanner.SERVICES}
    report["s3"] = {"status": "PARTIAL", "errors": ["one optional bucket field unavailable"]}
    scanner.scan_and_save(conn, [_public_bucket("bucket-partial")], collection_report=report)
    finding = next(item for item in get_findings(conn) if item["resource_id"] == "bucket-partial")
    partial, = get_finding_evidence(conn, finding["id"])
    assert partial["scan_status"] == "PARTIAL"

    failed_report = {name: {"status": "SUCCESS", "errors": []} for name in scanner.SERVICES}
    failed_report["s3"] = {"status": "FAILED", "errors": ["AccessDenied"]}
    scanner.scan_and_save(conn, [_public_bucket("bucket-partial")], collection_report=failed_report)
    assert len(get_finding_evidence(conn, finding["id"])) == 1
    conn.close()


def test_evidence_migration_is_repeatable_and_dashboard_page_has_control(tmp_path):
    path = str(tmp_path / "migration.db")
    first = connect(path)
    first.close()
    second = connect(path)
    assert second.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='finding_evidence'").fetchone()
    second.close()
    page = create_app().test_client().get("/")
    assert page.status_code == 200
    assert b"<th>Evidence</th>" in page.data
    assert b"Finding history" in page.data
