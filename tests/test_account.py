"""Seeing, connecting, switching and logging out of AWS accounts. AWS is faked: no real credentials are used."""
import json
import re

import boto3
import pytest
from botocore.exceptions import ClientError

from dashboard import account, auth, scanner
from dashboard.app import create_app

# Obviously fake values, assembled at runtime so no secret-shaped string sits in the source
# (GitHub secret scanning rightly blocks those, even when they are made up).
KEY = "AKIA" + "".join(["ABCDEFGH", "IJKLMNOP"])
OTHER_KEY = "AKIA" + "Z" * 16
SECRET = "".join(["abcdefghij", "klmnopqrst", "uvwxyzABCD", "EFGHIJKLMN"])
OTHER_SECRET = "".join(["NMLKJIHGFE", "DCBAzyxwvu", "tsrqponmlk", "jihgfedcba"])
AMBIENT = {"Account": "999999999999", "Arn": "arn:aws:iam::999999999999:user/ambient"}
KNOWN = {KEY: ("111111111111", "arn:aws:iam::111111111111:user/alpha"),
         OTHER_KEY: ("222222222222", "arn:aws:iam::222222222222:user/beta")}


def _fake_identity(**credentials):
    key = credentials.get("aws_access_key_id")
    if key is None:
        return AMBIENT
    if key not in KNOWN:
        raise ClientError({"Error": {"Code": "InvalidClientTokenId"}}, "GetCallerIdentity")
    account_id, arn = KNOWN[key]
    return {"Account": account_id, "Arn": arn}


@pytest.fixture(autouse=True)
def fresh_account(monkeypatch):
    for name in ("POLICYGUARD_BACKEND", "POLICYGUARD_SCANNER_FUNCTION", "POLICYGUARD_ACCOUNT_ID",
                 "POLICYGUARD_ACCOUNT_SCOPE", "POLICYGUARD_ALLOW_ACCOUNT_SWITCH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(account, "_caller_identity", _fake_identity)
    account.reset_for_tests()
    yield
    account.reset_for_tests()


def test_default_credentials_are_reported_as_the_monitored_account():
    current = account.current()
    assert current["state"] == "default" and current["connected"] is True
    assert current["account_id"] == "999999999999" and current["arn"] == AMBIENT["Arn"]


@pytest.mark.parametrize("key,secret,token,region,fragment", [
    ("nope", SECRET, None, None, "access key ID"),
    (KEY, "short", None, None, "secret access key"),
    ("ASIA" + KEY[4:], SECRET, None, None, "session token"),
    (KEY, SECRET, None, "Mumbai", "region"),
])
def test_malformed_input_is_rejected_before_calling_aws(monkeypatch, key, secret, token, region, fragment):
    monkeypatch.setattr(account, "_caller_identity", lambda **kw: pytest.fail("AWS must not be called"))
    with pytest.raises(account.AccountError, match=fragment):
        account.connect(key, secret, token, region)


def test_keys_aws_rejects_do_not_change_the_monitored_account():
    with pytest.raises(account.AccountError, match="rejected"):
        account.connect("AKIA" + "Q" * 16, SECRET, None, "ap-south-1")
    assert account.current()["state"] == "default" and account.connections() == []


def test_connect_monitors_the_new_account_and_never_exposes_the_secret():
    current = account.connect(KEY, SECRET, None, "ap-south-1")
    assert current["state"] == "session" and current["account_id"] == "111111111111"
    assert current["region"] == "ap-south-1" and current["key_hint"] == "…MNOP"
    exposed = json.dumps({"current": account.current(), "connections": account.connections()})
    assert SECRET not in exposed and KEY not in exposed
    # the scanner talks to AWS through boto3's default session, which now carries these keys
    credentials = boto3._get_default_session().get_credentials()
    assert credentials.access_key == KEY and credentials.secret_key == SECRET


def test_switching_between_connected_accounts():
    account.connect(KEY, SECRET, None, "ap-south-1")
    account.connect(OTHER_KEY, OTHER_SECRET, None, "us-east-1")
    assert account.current()["account_id"] == "222222222222"
    assert {c["account_id"]: c["active"] for c in account.connections()} == {"111111111111": False, "222222222222": True}

    assert account.switch("111111111111")["account_id"] == "111111111111"
    assert boto3._get_default_session().get_credentials().access_key == KEY
    with pytest.raises(account.AccountError, match="not connected"):
        account.switch("333333333333")


def test_logging_out_forgets_the_keys_and_pauses_scans():
    account.connect(KEY, SECRET, None, "ap-south-1")
    current = account.disconnect()
    assert current["state"] == "none" and current["connected"] is False
    assert account.connections() == []
    credentials = boto3._get_default_session().get_credentials()
    assert credentials is None or credentials.access_key != KEY
    with pytest.raises(account.NoAccountConnected):
        account.ensure_can_scan()
    with pytest.raises(account.NoAccountConnected):
        scanner.scan_and_save(None)


def test_default_credentials_can_be_resumed_after_logging_out():
    account.disconnect()
    assert account.current()["state"] == "none"
    assert account.use_default()["state"] == "default"
    account.ensure_can_scan()


def test_forgetting_an_inactive_account_keeps_the_active_one():
    account.connect(KEY, SECRET, None, "ap-south-1")
    account.connect(OTHER_KEY, OTHER_SECRET, None, "us-east-1")
    account.disconnect("111111111111")
    assert [c["account_id"] for c in account.connections()] == ["222222222222"]
    assert account.current()["account_id"] == "222222222222"


@pytest.mark.parametrize("name,value", [("POLICYGUARD_BACKEND", "dynamodb"), ("POLICYGUARD_ACCOUNT_ID", "123456789012"),
                                        ("POLICYGUARD_ALLOW_ACCOUNT_SWITCH", "false")])
def test_switching_is_blocked_when_the_account_is_fixed_by_the_deployment(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(account.AccountError):
        account.connect(KEY, SECRET, None, "ap-south-1")
    with pytest.raises(account.AccountError):
        account.disconnect()


# ---- HTTP API: roles, CSRF and the unauthenticated-mode guard -------------------------------------------------

USERS = "viewer1:view-pass:viewer;admin1:admin-pass:admin"


def _login(client, user, password):
    token = re.search(rb'name="csrf" value="([^"]+)"', client.get("/login").data).group(1).decode()
    return client.post("/login", data={"username": user, "password": password, "csrf": token})


@pytest.fixture
def secured_app(monkeypatch, tmp_path):
    monkeypatch.setenv("POLICYGUARD_AUTH", "local")
    monkeypatch.setenv("POLICYGUARD_LOCAL_USERS", USERS)
    monkeypatch.setenv("POLICYGUARD_SECRET_KEY", "test-secret")
    monkeypatch.setenv("POLICYGUARD_DB", str(tmp_path / "a.db"))
    monkeypatch.setattr("db.schema.DB_PATH", str(tmp_path / "a.db"))
    auth._failures.clear()
    return create_app()


def _post(client, url, body, token=None):
    headers = {"X-CSRF-Token": token} if token else {}
    return client.post(url, json=body, headers=headers)


def test_everyone_signed_in_can_see_the_monitored_account(secured_app):
    viewer = secured_app.test_client()
    _login(viewer, "viewer1", "view-pass")
    data = viewer.get("/api/account").get_json()
    assert data["current"]["account_id"] == "999999999999" and data["switching"]["allowed"] is True
    assert viewer.get("/account").status_code == 200


def test_only_admins_with_a_csrf_token_can_change_the_account(secured_app):
    viewer, admin = secured_app.test_client(), secured_app.test_client()
    _login(viewer, "viewer1", "view-pass")
    _login(admin, "admin1", "admin-pass")
    body = {"access_key_id": KEY, "secret_access_key": SECRET, "region": "ap-south-1"}

    assert _post(viewer, "/api/account/connect", body, viewer.get("/api/me").get_json()["csrf"]).status_code == 403
    assert _post(admin, "/api/account/connect", body).status_code == 400          # no CSRF token

    response = _post(admin, "/api/account/connect", body, admin.get("/api/me").get_json()["csrf"])
    assert response.status_code == 200
    assert response.get_json()["current"]["account_id"] == "111111111111"
    assert SECRET not in response.get_data(as_text=True)


def test_bad_keys_return_a_clear_error_not_a_server_error(secured_app):
    admin = secured_app.test_client()
    _login(admin, "admin1", "admin-pass")
    response = _post(admin, "/api/account/connect", {"access_key_id": "bad", "secret_access_key": SECRET},
                     admin.get("/api/me").get_json()["csrf"])
    assert response.status_code == 400 and "access key ID" in response.get_json()["error"]


def test_with_sign_in_off_only_this_computer_may_change_the_account(monkeypatch):
    monkeypatch.setenv("POLICYGUARD_AUTH", "off")
    client = create_app().test_client()
    body = {"access_key_id": KEY, "secret_access_key": SECRET, "region": "ap-south-1"}
    remote = client.post("/api/account/connect", json=body, environ_overrides={"REMOTE_ADDR": "10.0.0.7"})
    assert remote.status_code == 403
    assert account.current()["state"] == "default"
    local = client.post("/api/account/connect", json=body, environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    assert local.status_code == 200 and local.get_json()["current"]["account_id"] == "111111111111"


def test_scan_now_says_so_when_no_account_is_connected(monkeypatch):
    monkeypatch.setenv("POLICYGUARD_AUTH", "off")
    account.disconnect()
    response = create_app().test_client().post("/api/scan")
    assert response.status_code == 409 and "No AWS account" in response.get_json()["detail"]


# ---- data follows the active account -------------------------------------------------------------------------

def test_views_follow_the_active_account_once_two_accounts_have_history(tmp_path, monkeypatch):
    import dashboard.routes.compliance_score as score_route
    import dashboard.routes.violations as findings_route
    from db.schema import connect as db_connect, get_findings

    open_ssh = {"resource_type": "security_group", "provider": "aws", "resource_id": "sg-123", "tags": {},
                "permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
    database = str(tmp_path / "scope.db")
    conn = db_connect(database)
    monkeypatch.setattr(scanner, "_region_scope", lambda: "ap-south-1")
    monkeypatch.setattr(scanner, "remediate_violations", lambda findings: [])
    for scope in ("111111111111", "222222222222"):
        monkeypatch.setattr(scanner, "_account_scope", lambda scope=scope: scope)
        scanner.scan_and_save(conn, resources=[open_ssh])
    assert {f["account_scope"] for f in get_findings(conn)} == {"111111111111", "222222222222"}

    monkeypatch.setenv("POLICYGUARD_AUTH", "off")
    factory = lambda: db_connect(database)
    monkeypatch.setattr(findings_route, "connect", factory)
    monkeypatch.setattr(score_route, "connect", factory)
    client = create_app().test_client()

    account.connect(KEY, SECRET, None, "ap-south-1")                       # monitoring 111111111111
    assert {f["account_scope"] for f in client.get("/api/findings").get_json()} == {"111111111111"}
    assert client.get("/api/compliance-score").get_json()["scan"]["account_scope"] == "111111111111"

    account.connect(OTHER_KEY, OTHER_SECRET, None, "us-east-1")            # now 222222222222
    assert {f["account_scope"] for f in client.get("/api/findings").get_json()} == {"222222222222"}
    assert {v["account_scope"] for v in client.get("/api/violations").get_json()} == {"222222222222"}
    assert client.get("/api/compliance-score").get_json()["scan"]["account_scope"] == "222222222222"


def test_with_a_single_account_everything_is_shown(tmp_path, monkeypatch):
    from db.schema import connect as db_connect
    conn = db_connect(str(tmp_path / "one.db"))
    monkeypatch.setattr(scanner, "_account_scope", lambda: "111111111111")
    monkeypatch.setattr(scanner, "_region_scope", lambda: "ap-south-1")
    monkeypatch.setattr(scanner, "remediate_violations", lambda findings: [])
    scanner.scan_and_save(conn, resources=[])
    assert account.visible_scope(conn) is None


# ---- bugs found while clicking through the dashboard ---------------------------------------------------------

def test_guardduty_not_subscribed_means_threat_detection_is_off_not_a_failed_read(monkeypatch):
    from lambdas.rule_engine import handler

    class Logs:
        def get_paginator(self, name):
            return type("P", (), {"paginate": lambda self: [{"logGroups": []}]})()

    class GuardDuty:
        def list_detectors(self):
            raise ClientError({"Error": {"Code": "SubscriptionRequiredException"}}, "ListDetectors")

    monkeypatch.setattr(handler.boto3, "client", lambda name, **kw: Logs() if name == "logs" else GuardDuty())
    report = {"cloudtrail": {"status": "SUCCESS", "errors": []}}
    extra = handler._collect_logging_and_detection("ap-south-1", report)
    assert extra["guardduty_enabled"] is False
    assert "GuardDuty" not in json.dumps(report)


def test_cost_estimate_ignores_legacy_scans_recorded_with_zero_duration(tmp_path, monkeypatch):
    import dashboard.routes.insight as insight
    legacy = {"status": "PARTIAL", "account_scope": "legacy", "started_at": "2026-10-06T09:00:00", "completed_at": "2026-10-06T09:00:00"}
    real = {"status": "COMPLETED", "account_scope": "111111111111", "started_at": "2026-11-17T00:00:00+00:00",
            "completed_at": "2026-11-17T00:00:30+00:00"}
    monkeypatch.setattr(insight, "_with_store", lambda fn: [legacy] * 50 + [real])
    monkeypatch.setenv("POLICYGUARD_AUTH", "off")
    cost = create_app().test_client().get("/api/usage").get_json()["cost"]
    assert cost["available"] is True and cost["avg_scan_seconds"] == 30.0


def test_failed_sign_in_keeps_the_username_but_never_the_password_and_escapes_it(secured_app):
    client = secured_app.test_client()
    token = re.search(rb'name="csrf" value="([^"]+)"', client.get("/login").data).group(1).decode()
    response = client.post("/login", data={"username": 'bob"><script>x</script>', "password": "wrong-pass", "csrf": token})
    html = response.get_data(as_text=True)
    assert response.status_code == 401 and "Incorrect username or password." in html
    assert "wrong-pass" not in html
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html       # the echoed username is escaped
