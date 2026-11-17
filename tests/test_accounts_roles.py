"""Cross-account monitored accounts: the handshake, roles, isolation between accounts, and the account selector."""
import re

import pytest
from botocore.exceptions import ClientError

from dashboard import auth, monitored, scanner
from dashboard.app import create_app
from db import schema
from db.store import append_audit_events, get_audit_log, get_findings, get_violations
from lambdas.audit_logger.hash_chain import verify_chain

HOME = "111111111111"
OTHER = "222222222222"
USERS = "viewer1:view-pass:viewer;audit1:audit-pass:auditor;admin1:admin-pass:admin"


@pytest.fixture
def env(monkeypatch, tmp_path):
    db_path = str(tmp_path / "m.db")
    monkeypatch.setattr("db.schema.DB_PATH", db_path)
    monkeypatch.setenv("POLICYGUARD_HOME_ACCOUNT_ID", HOME)
    monkeypatch.setenv("POLICYGUARD_SECRET_KEY", "test-secret")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    monkeypatch.setattr(monitored, "_assume", lambda account: {"AccessKeyId": "x", "SecretAccessKey": "y", "SessionToken": "z"})
    auth._failures.clear()
    return schema.connect(db_path)


def local_app(monkeypatch):
    monkeypatch.setenv("POLICYGUARD_AUTH", "local")
    monkeypatch.setenv("POLICYGUARD_LOCAL_USERS", USERS)
    return create_app()


def login(client, user, password):
    token = re.search(rb'name="csrf" value="([^"]+)"', client.get("/login").data).group(1).decode()
    client.post("/login", data={"username": user, "password": password, "csrf": token})
    return client.get("/api/me").get_json()["csrf"]


# ---- the handshake ----
def test_register_creates_a_pending_account_with_an_external_id_and_logs_it(env):
    account = monitored.create(env, "Production", OTHER, "ap-south-1", "pgadmin")
    assert account["status"] == "PENDING" and account["enabled"] is False
    assert account["role_arn"] == f"arn:aws:iam::{OTHER}:role/PolicyGuardReadOnly"
    assert len(account["external_id"]) >= 24
    chain = get_audit_log(env)
    assert chain[-1]["event_type"] == "ACCOUNT_REGISTERED" and chain[-1]["details"]["actor"] == "pgadmin" and verify_chain(chain)
    assert "external_id" not in monitored.public_view(account)


@pytest.mark.parametrize("name,account_id,region,message", [
    ("", OTHER, "ap-south-1", "name"), ("Prod", "12345", "ap-south-1", "12 digits"),
    ("Prod", OTHER, "mars-1", "region"), ("Prod", HOME, "ap-south-1", "already monitored")])
def test_register_rejects_bad_input(env, name, account_id, region, message):
    with pytest.raises(monitored.AccountError) as error:
        monitored.create(env, name, account_id, region, "pgadmin")
    assert message in str(error.value)


def test_duplicate_registration_is_refused(env):
    monitored.create(env, "A", OTHER, "ap-south-1", "pgadmin")
    with pytest.raises(monitored.AccountError):
        monitored.create(env, "A again", OTHER, "ap-south-1", "pgadmin")


def test_verify_success_activates_and_failure_keeps_it_pending(env, monkeypatch):
    monitored.create(env, "A", OTHER, "ap-south-1", "pgadmin")

    def denied(account):
        raise ClientError({"Error": {"Code": "AccessDenied"}}, "AssumeRole")
    monkeypatch.setattr(monitored, "_assume", denied)
    with pytest.raises(monitored.AccountError) as error:
        monitored.verify(env, OTHER, "pgadmin")
    assert "External ID" in str(error.value) and monitored.get_account(env, OTHER)["status"] == "PENDING"

    monkeypatch.setattr(monitored, "_assume", lambda a: {"AccessKeyId": "x", "SecretAccessKey": "y", "SessionToken": "z"})
    account = monitored.verify(env, OTHER, "pgadmin")
    assert account["status"] == "ACTIVE" and account["enabled"] is True and account["last_error"] is None


def test_unverified_accounts_cannot_be_enabled(env):
    monitored.create(env, "A", OTHER, "ap-south-1", "pgadmin")
    with pytest.raises(monitored.AccountError):
        monitored.set_enabled(env, OTHER, True, "pgadmin")


def test_instructions_include_the_template_command_and_trusted_roles(env, monkeypatch):
    monkeypatch.setenv("POLICYGUARD_SCANNER_ROLE_ARN", f"arn:aws:iam::{HOME}:role/scanner")
    monkeypatch.setenv("POLICYGUARD_INSTANCE_ROLE_ARN", f"arn:aws:iam::{HOME}:role/instance")
    info = monitored.instructions(monitored.create(env, "A", OTHER, "ap-south-1", "pgadmin"))
    assert "member-account-role.yaml" in info["deploy_command"] and "CAPABILITY_NAMED_IAM" in info["deploy_command"]
    assert info["parameters"]["TrustedRoleArns"].count("role/") == 2 and info["parameters"]["ExternalId"]


# ---- roles: auditors may look, only admins change ----
def test_only_admins_can_change_accounts_and_only_admins_see_the_external_id(env, monkeypatch):
    app = local_app(monkeypatch)
    viewer, auditor, admin = (app.test_client() for _ in range(3))
    vcsrf, acsrf, ccsrf = login(viewer, "viewer1", "view-pass"), login(auditor, "audit1", "audit-pass"), login(admin, "admin1", "admin-pass")
    body = {"name": "Prod", "account_id": OTHER, "region": "ap-south-1"}

    assert viewer.get("/accounts").status_code == 403 and viewer.get("/api/monitored-accounts").status_code == 403
    assert auditor.get("/accounts").status_code == 200 and auditor.get("/api/monitored-accounts").status_code == 200
    assert auditor.post("/api/monitored-accounts", json=body, headers={"X-CSRF-Token": acsrf}).status_code == 403
    assert admin.post("/api/monitored-accounts", json=body).status_code == 400            # CSRF missing

    created = admin.post("/api/monitored-accounts", json=body, headers={"X-CSRF-Token": ccsrf})
    assert created.status_code == 201 and created.get_json()["instructions"]["parameters"]["ExternalId"]
    listing = auditor.get("/api/monitored-accounts").get_json()
    assert listing["accounts"][0]["account_id"] == OTHER and "external_id" not in str(listing)
    assert auditor.get(f"/api/monitored-accounts/{OTHER}/instructions").status_code == 403
    template = admin.get(f"/api/monitored-accounts/{OTHER}/template")
    assert template.status_code == 200 and b"ScannerReadOnlyRole" in template.data


# ---- scanning: isolation between accounts ----
def _sg(rid, open_=True):
    perms = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}] if open_ else []
    return {"resource_type": "security_group", "provider": "aws", "resource_id": rid, "region": "ap-south-1",
            "permissions": perms, "tags": {}}


def _scan(conn, monkeypatch, account_id, resources):
    monkeypatch.setattr(scanner, "_account_scope", lambda: account_id)
    monkeypatch.setattr(scanner, "_region_scope", lambda: "ap-south-1")
    monkeypatch.setattr(scanner, "remediate_violations", lambda findings: [])
    return scanner.scan_and_save(conn, resources)


def test_one_accounts_scan_never_resolves_or_duplicates_another_accounts_findings(env, monkeypatch):
    shared_id = "sg-shared"                                 # the same rule + resource id exists in both accounts
    _scan(env, monkeypatch, HOME, [_sg(shared_id)])
    second = _scan(env, monkeypatch, OTHER, [_sg(shared_id)])
    assert second["new"] == 1                               # a new finding for the other account, not "already known"
    _scan(env, monkeypatch, OTHER, [_sg(shared_id, open_=False)])    # fixed in the OTHER account only
    by_scope = {(f["account_scope"], f["status"]) for f in get_findings(env) if f["rule"] == "open_admin_ports"}
    assert by_scope == {(HOME, "NEW"), (OTHER, "RESOLVED")}
    resolved = [e for e in get_audit_log(env) if e["event_type"] == "VIOLATION_RESOLVED"]
    assert len(resolved) == 1                               # exactly the OTHER account's fix, none for HOME
    assert [f["account_scope"] for f in get_violations(env)] == [HOME]


class _KeepOpen:
    """The scanner closes its connection when done; the test still needs to read the database afterwards."""
    def __init__(self, conn):
        self._conn = conn

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __enter__(self):
        return self._conn.__enter__()

    def __exit__(self, *args):
        return self._conn.__exit__(*args)

    def close(self):
        pass


def test_lambda_scans_home_then_active_members_and_isolates_failures(env, monkeypatch):
    from db.store import put_doc
    from lambdas.scanner import handler
    monitored.create(env, "Good", OTHER, "ap-south-1", "pgadmin")
    monitored.verify(env, OTHER, "pgadmin")
    monitored.create(env, "Broken", "333333333333", "ap-south-1", "pgadmin")
    broken = monitored.get_account(env, "333333333333")
    broken.update(status="ACTIVE", enabled=True)
    put_doc(env, "accounts", "333333333333", broken)
    monitored.create(env, "Pending", "444444444444", "ap-south-1", "pgadmin")     # never verified: must be skipped

    calls = []

    def fake_scan(conn, account=None):
        calls.append(account["account_id"] if account else "home")
        if account and account["account_id"] == "333333333333":
            raise RuntimeError("could not assume role")
        return {"status": "COMPLETED", "scan_id": len(calls), "account_scope": account["account_id"] if account else HOME,
                "violations": 0, "resources_assessed": 5}, [], []
    monkeypatch.setattr(handler, "_scan_one", fake_scan)
    monkeypatch.setattr(handler, "_anchor", lambda r: {"anchored": False, "reason": "not configured"})
    monkeypatch.setattr("db.store.connect", lambda path=None: _KeepOpen(env))

    result = handler.lambda_handler({}, None)
    assert calls == ["home", OTHER, "333333333333"]
    assert {a["account_id"]: a["status"] for a in result["accounts"]} == {OTHER: "COMPLETED", "333333333333": "FAILED"}
    assert monitored.get_account(env, "333333333333")["last_scan_status"] == "FAILED"
    assert monitored.get_account(env, OTHER)["last_scan_status"] == "COMPLETED"
    assert monitored.get_account(env, "444444444444").get("last_scan_status") is None

    calls.clear()
    handler.lambda_handler({"account_id": OTHER}, None)
    assert calls == [OTHER]                                  # only the requested member account


# ---- the account selector ----
def test_selector_filters_every_page_to_the_chosen_account(env, monkeypatch):
    from dashboard import account as account_module
    monkeypatch.setenv("POLICYGUARD_AUTH", "off")
    monkeypatch.setattr(account_module, "active_account_id", lambda: HOME)   # no real STS call from a test
    _scan(env, monkeypatch, HOME, [_sg("sg-home")])
    _scan(env, monkeypatch, OTHER, [_sg("sg-other-1"), _sg("sg-other-2")])
    client = create_app().test_client()
    view = client.get("/api/view").get_json()
    assert [o["id"] for o in view["options"]] == [HOME, OTHER, "ALL"] and view["current"] == HOME
    assert len(client.get("/api/findings").get_json()) == 1

    assert client.post("/api/view", json={"account_id": OTHER}).status_code == 200
    assert len(client.get("/api/findings").get_json()) == 2
    assert client.get("/api/compliance-score").get_json()["scan"]["account_scope"] == OTHER

    client.post("/api/view", json={"account_id": "ALL"})
    assert len(client.get("/api/findings").get_json()) == 3
    assert client.post("/api/view", json={"account_id": "999999999999"}).status_code == 400
