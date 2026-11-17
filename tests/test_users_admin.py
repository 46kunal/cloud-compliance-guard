"""Admin user management against a mocked Cognito pool: creation, roles, guards and the audit trail."""
import re

import pytest

moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")

from dashboard import auth, users
from dashboard.app import create_app
from db import schema
from db.store import get_audit_log
from lambdas.audit_logger.hash_chain import verify_chain


@pytest.fixture
def pool(monkeypatch, tmp_path):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_DEFAULT_REGION": "ap-south-1"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("db.schema.DB_PATH", str(tmp_path / "u.db"))
    with moto.mock_aws():
        cognito = boto3.client("cognito-idp")
        pool_id = cognito.create_user_pool(PoolName="pg")["UserPool"]["Id"]
        client_id = cognito.create_user_pool_client(UserPoolId=pool_id, ClientName="c",
                                                    ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"])["UserPoolClient"]["ClientId"]
        for group in users.ROLES:
            cognito.create_group(UserPoolId=pool_id, GroupName=group)
        for name, role in (("boss", "admin"), ("analyst", "auditor")):
            cognito.admin_create_user(UserPoolId=pool_id, Username=name, MessageAction="SUPPRESS",
                                      UserAttributes=[{"Name": "email", "Value": f"{name}@example.com"}])
            cognito.admin_set_user_password(UserPoolId=pool_id, Username=name, Password="Perm#Pass12345", Permanent=True)
            cognito.admin_add_user_to_group(UserPoolId=pool_id, Username=name, GroupName=role)
        monkeypatch.setenv("POLICYGUARD_AUTH", "cognito")
        monkeypatch.setenv("COGNITO_USER_POOL_ID", pool_id)
        monkeypatch.setenv("COGNITO_CLIENT_ID", client_id)
        monkeypatch.setenv("COGNITO_REGION", "ap-south-1")
        monkeypatch.setenv("POLICYGUARD_SECRET_KEY", "test-secret")
        auth._failures.clear()
        yield schema.connect(str(tmp_path / "u.db"))


def test_list_shows_each_users_role(pool):
    assert {(u["username"], u["role"]) for u in users.list_users()} == {("boss", "admin"), ("analyst", "auditor")}


def test_create_user_adds_them_to_the_chosen_group_and_is_audited(pool):
    users.create_user(pool, "asha", "asha@example.com", "viewer", "boss")
    asha = next(u for u in users.list_users() if u["username"] == "asha")
    assert asha["role"] == "viewer" and asha["status"] == "FORCE_CHANGE_PASSWORD" and asha["email"] == "asha@example.com"
    chain = get_audit_log(pool)
    assert chain[-1]["event_type"] == "USER_CREATED" and chain[-1]["details"] == {"actor": "boss", "username": "asha", "role": "viewer"}
    assert verify_chain(chain)


@pytest.mark.parametrize("name,email,role", [("a", "x@y.com", "viewer"), ("good", "not-an-email", "viewer"), ("good", "x@y.com", "root")])
def test_create_rejects_bad_input(pool, name, email, role):
    with pytest.raises(users.UserError):
        users.create_user(pool, name, email, role, "boss")


def test_duplicate_username_is_refused(pool):
    with pytest.raises(users.UserError):
        users.create_user(pool, "analyst", "a@b.com", "viewer", "boss")


def test_changing_role_moves_the_user_between_groups(pool):
    users.set_role(pool, "analyst", "viewer", "boss")
    assert next(u for u in users.list_users() if u["username"] == "analyst")["role"] == "viewer"
    assert get_audit_log(pool)[-1]["details"]["old_role"] == "auditor"


def test_nobody_can_change_disable_or_delete_themselves(pool):
    for action in (lambda: users.set_role(pool, "boss", "viewer", "boss"), lambda: users.set_enabled(pool, "boss", False, "boss"),
                   lambda: users.delete_user(pool, "boss", "boss")):
        with pytest.raises(users.UserError):
            action()


def test_the_last_enabled_admin_cannot_be_removed_or_demoted(pool):
    with pytest.raises(users.UserError) as error:
        users.set_role(pool, "boss", "viewer", "analyst")
    assert "no enabled admin" in str(error.value)
    with pytest.raises(users.UserError):
        users.set_enabled(pool, "boss", False, "analyst")
    with pytest.raises(users.UserError):
        users.delete_user(pool, "boss", "analyst")
    users.set_role(pool, "analyst", "admin", "boss")          # a second admin makes it allowed
    users.set_role(pool, "boss", "viewer", "analyst")
    assert next(u for u in users.list_users() if u["username"] == "boss")["role"] == "viewer"


def test_disable_enable_and_delete(pool):
    users.create_user(pool, "temp", "t@example.com", "viewer", "boss")
    users.set_enabled(pool, "temp", False, "boss")
    assert next(u for u in users.list_users() if u["username"] == "temp")["enabled"] is False
    users.set_enabled(pool, "temp", True, "boss")
    users.delete_user(pool, "temp", "boss")
    assert "temp" not in [u["username"] for u in users.list_users()]
    assert [e["event_type"] for e in get_audit_log(pool)][-4:] == ["USER_CREATED", "USER_DISABLED", "USER_ENABLED", "USER_DELETED"]


def test_resend_invitation_only_for_users_who_never_signed_in(pool):
    users.create_user(pool, "newbie", "n@example.com", "viewer", "boss")
    users.resend_invitation(pool, "newbie", "boss")
    with pytest.raises(users.UserError):
        users.resend_invitation(pool, "analyst", "boss")


def _login(client, name):
    token = re.search(rb'name="csrf" value="([^"]+)"', client.get("/login").data).group(1).decode()
    client.post("/login", data={"username": name, "password": "Perm#Pass12345", "csrf": token})
    return client.get("/api/me").get_json()["csrf"]


def test_only_admins_reach_the_users_api_and_it_works_end_to_end(pool):
    app = create_app()
    admin, auditor = app.test_client(), app.test_client()
    csrf = _login(admin, "boss")
    _login(auditor, "analyst")
    assert auditor.get("/users").status_code == 403 and auditor.get("/api/users").status_code == 403
    assert admin.get("/users").status_code == 200
    listing = admin.get("/api/users").get_json()
    assert listing["managed"] and listing["me"] == "boss"
    created = admin.post("/api/users", json={"username": "kunal2", "email": "k@example.com", "role": "auditor"},
                         headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200 and "kunal2" in str(created.get_json())
    assert admin.post("/api/users/boss/disable", headers={"X-CSRF-Token": csrf}).status_code == 400   # cannot disable yourself
    assert admin.post("/api/users", json={"username": "x"}).status_code == 400                         # CSRF missing


def test_local_mode_is_read_only(monkeypatch, tmp_path):
    monkeypatch.setenv("POLICYGUARD_AUTH", "local")
    monkeypatch.setenv("POLICYGUARD_LOCAL_USERS", "admin1:pw:admin;view1:pw:viewer")
    monkeypatch.setenv("POLICYGUARD_SECRET_KEY", "s")
    monkeypatch.setattr("db.schema.DB_PATH", str(tmp_path / "l.db"))
    app = create_app()
    client = app.test_client()
    token = re.search(rb'name="csrf" value="([^"]+)"', client.get("/login").data).group(1).decode()
    client.post("/login", data={"username": "admin1", "password": "pw", "csrf": token})
    csrf = client.get("/api/me").get_json()["csrf"]
    data = client.get("/api/users").get_json()
    assert data["managed"] is False and {u["username"] for u in data["users"]} == {"admin1", "view1"}
    assert client.post("/api/users", json={"username": "abc", "email": "a@b.co", "role": "viewer"},
                       headers={"X-CSRF-Token": csrf}).status_code == 400
