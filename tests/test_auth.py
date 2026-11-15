"""Login, roles, CSRF and Cognito sign-in (Cognito is mocked with moto; no real AWS)."""
import re

import pytest

from dashboard import auth
from dashboard.app import create_app

USERS = "viewer1:view-pass:viewer;audit1:audit-pass:auditor;admin1:admin-pass:admin"


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("POLICYGUARD_AUTH", "local")
    monkeypatch.setenv("POLICYGUARD_LOCAL_USERS", USERS)
    monkeypatch.setenv("POLICYGUARD_SECRET_KEY", "test-secret")
    monkeypatch.setenv("POLICYGUARD_DB", str(tmp_path / "auth.db"))
    monkeypatch.setattr("db.schema.DB_PATH", str(tmp_path / "auth.db"))
    auth._failures.clear()
    return create_app()


def _csrf(html: bytes) -> str:
    return re.search(rb'name="csrf" value="([^"]+)"', html).group(1).decode()


def login(client, user, password):
    token = _csrf(client.get("/login").data)
    return client.post("/login", data={"username": user, "password": password, "csrf": token})


def api_csrf(client):
    return client.get("/api/me").get_json()["csrf"]


def test_pages_and_api_require_login(app):
    client = app.test_client()
    page = client.get("/")
    assert page.status_code == 302 and "/login" in page.headers["Location"]
    assert client.get("/api/findings").status_code == 401
    assert client.get("/health").status_code == 200


def test_wrong_password_is_rejected_and_good_password_signs_in(app):
    client = app.test_client()
    assert login(client, "admin1", "nope").status_code == 401
    ok = login(client, "admin1", "admin-pass")
    assert ok.status_code == 302
    assert client.get("/api/me").get_json()["role"] == "admin"


def test_login_form_without_csrf_token_is_refused(app):
    client = app.test_client()
    client.get("/login")
    assert client.post("/login", data={"username": "admin1", "password": "admin-pass"}).status_code == 400


def test_roles_limit_what_each_user_can_reach(app):
    viewer, auditor, admin = (app.test_client() for _ in range(3))
    login(viewer, "viewer1", "view-pass")
    login(auditor, "audit1", "audit-pass")
    login(admin, "admin1", "admin-pass")

    assert viewer.get("/findings").status_code == 200
    assert viewer.get("/audit").status_code == 403
    assert viewer.get("/api/audit-log").status_code == 403
    assert viewer.get("/api/findings/1/evidence").status_code == 403
    assert viewer.get("/api/export/findings.csv").status_code == 403

    assert auditor.get("/audit").status_code == 200
    assert auditor.get("/api/export/findings.csv").status_code == 200
    assert auditor.post("/api/scan", headers={"X-CSRF-Token": api_csrf(auditor)}).status_code == 403

    assert admin.get("/audit").status_code == 200


def test_state_changing_requests_need_csrf_token(app, monkeypatch):
    monkeypatch.setattr("dashboard.app._run_scan", lambda: {"status": "COMPLETED"})
    client = app.test_client()
    login(client, "admin1", "admin-pass")
    assert client.post("/api/scan").status_code == 400
    assert client.post("/api/scan", headers={"X-CSRF-Token": "wrong"}).status_code == 400
    assert client.post("/api/scan", headers={"X-CSRF-Token": api_csrf(client)}).status_code == 200


def test_logout_ends_the_session(app):
    client = app.test_client()
    login(client, "viewer1", "view-pass")
    token = api_csrf(client)
    assert client.post("/logout", data={"csrf": token}).status_code == 302
    assert client.get("/api/findings").status_code == 401


def test_repeated_failures_are_rate_limited(app):
    client = app.test_client()
    codes = [login(client, "admin1", "bad").status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    assert login(client, "admin1", "admin-pass").status_code == 429


def test_security_headers_present(app):
    response = app.test_client().get("/login")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_auth_off_keeps_everything_open(monkeypatch, tmp_path):
    monkeypatch.setenv("POLICYGUARD_AUTH", "off")
    monkeypatch.setenv("POLICYGUARD_DB", str(tmp_path / "x.db"))
    monkeypatch.setattr("db.schema.DB_PATH", str(tmp_path / "x.db"))
    client = create_app().test_client()
    assert client.get("/").status_code == 200 and client.get("/api/me").get_json()["role"] == "admin"


# ---- Cognito ----
moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")


@pytest.fixture
def cognito(monkeypatch, tmp_path):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_DEFAULT_REGION": "ap-south-1"}.items():
        monkeypatch.setenv(key, value)
    with moto.mock_aws():
        client = boto3.client("cognito-idp")
        pool = client.create_user_pool(PoolName="pg", Policies={"PasswordPolicy": {"MinimumLength": 12}})["UserPool"]["Id"]
        app_client = client.create_user_pool_client(
            UserPoolId=pool, ClientName="dash", ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
        )["UserPoolClient"]["ClientId"]
        for group in ("viewer", "auditor", "admin"):
            client.create_group(UserPoolId=pool, GroupName=group)
        client.admin_create_user(UserPoolId=pool, Username="asha", TemporaryPassword="Temp#Pass1234", MessageAction="SUPPRESS")
        client.admin_set_user_password(UserPoolId=pool, Username="asha", Password="Perm#Pass12345", Permanent=True)
        client.admin_add_user_to_group(UserPoolId=pool, Username="asha", GroupName="auditor")
        monkeypatch.setenv("POLICYGUARD_AUTH", "cognito")
        monkeypatch.setenv("COGNITO_CLIENT_ID", app_client)
        monkeypatch.setenv("COGNITO_REGION", "ap-south-1")
        monkeypatch.setenv("POLICYGUARD_SECRET_KEY", "test-secret")
        monkeypatch.setenv("POLICYGUARD_DB", str(tmp_path / "c.db"))
        monkeypatch.setattr("db.schema.DB_PATH", str(tmp_path / "c.db"))
        auth._failures.clear()
        yield create_app().test_client()


def test_cognito_sign_in_maps_group_to_role(cognito):
    assert login(cognito, "asha", "Perm#Pass12345").status_code == 302
    me = cognito.get("/api/me").get_json()
    assert me["username"] == "asha" and me["role"] == "auditor" and me["auth"] == "cognito"


def test_cognito_wrong_password_is_rejected(cognito):
    assert login(cognito, "asha", "wrong-password").status_code == 401
    assert login(cognito, "nobody", "whatever-123456").status_code == 401


def test_role_from_groups_picks_highest():
    assert auth._role_from_groups(["viewer", "admin"]) == "admin"
    assert auth._role_from_groups([]) == "viewer"
    assert auth._role_from_groups(["unknown"]) == "viewer"
