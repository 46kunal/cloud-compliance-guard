"""Admin user management on top of the Cognito user pool.

Logins live in Cognito, not in PolicyGuard. This module creates users (Cognito emails them a temporary password),
moves them between the viewer / auditor / admin groups, disables or deletes them, and writes each change to the
audit chain. Safety rules: nobody can change their own role, disable or delete themselves, and the last
enabled admin can never be removed or demoted.
"""
import os
import re

ROLES = ("viewer", "auditor", "admin")
USERNAME = re.compile(r"^[A-Za-z0-9._-]{3,40}$")
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


class UserError(Exception):
    """A problem with a request; the message is safe to show."""


def pool_id():
    return os.environ.get("COGNITO_USER_POOL_ID")


def managed() -> bool:
    return os.environ.get("POLICYGUARD_AUTH", "off").lower() == "cognito" and bool(pool_id())


def _client():
    import boto3
    return boto3.client("cognito-idp", region_name=os.environ.get("COGNITO_REGION") or os.environ.get("AWS_REGION"))


def _attr(user, name):
    for item in user.get("Attributes", user.get("UserAttributes", [])):
        if item["Name"] == name:
            return item["Value"]
    return None


def _role_of(client, username):
    groups = client.admin_list_groups_for_user(UserPoolId=pool_id(), Username=username).get("Groups", [])
    best = "viewer"
    for group in groups:
        if group["GroupName"] in ROLES and ROLES.index(group["GroupName"]) > ROLES.index(best):
            best = group["GroupName"]
    return best


def list_users(client=None) -> list:
    client = client or _client()
    users, token = [], None
    while True:
        kwargs = {"UserPoolId": pool_id()}
        if token:
            kwargs["PaginationToken"] = token
        page = client.list_users(**kwargs)
        for user in page.get("Users", []):
            users.append({"username": user["Username"], "email": _attr(user, "email"), "status": user.get("UserStatus"),
                          "enabled": user.get("Enabled", True), "role": _role_of(client, user["Username"]),
                          "created": user["UserCreateDate"].isoformat() if user.get("UserCreateDate") else None})
        token = page.get("PaginationToken")
        if not token:
            break
    return sorted(users, key=lambda u: u["username"].lower())


def _enabled_admins(users):
    return [u for u in users if u["role"] == "admin" and u["enabled"]]


def _audit(conn, event, actor, **details):
    from db.store import append_audit_events
    append_audit_events(conn, [(event, {"actor": actor, **details})])


def create_user(conn, username, email, role, actor, client=None):
    client = client or _client()
    username, email, role = (username or "").strip(), (email or "").strip(), (role or "").strip()
    if not USERNAME.match(username):
        raise UserError("The username needs 3 to 40 letters, numbers, dots, dashes or underscores.")
    if not EMAIL.match(email):
        raise UserError("Enter a valid email address. Cognito sends the temporary password there.")
    if role not in ROLES:
        raise UserError("Choose a role: viewer, auditor or admin.")
    try:
        client.admin_create_user(
            UserPoolId=pool_id(), Username=username, DesiredDeliveryMediums=["EMAIL"],
            UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}])
    except client.exceptions.UsernameExistsException:
        raise UserError("That username already exists.")
    client.admin_add_user_to_group(UserPoolId=pool_id(), Username=username, GroupName=role)
    _audit(conn, "USER_CREATED", actor, username=username, role=role)


def _require_other_admin_remains(users, username):
    remaining = [u for u in _enabled_admins(users) if u["username"] != username]
    if not remaining:
        raise UserError("That would leave no enabled admin. Make someone else an admin first.")


def set_role(conn, username, role, actor, client=None):
    client = client or _client()
    if role not in ROLES:
        raise UserError("Choose a role: viewer, auditor or admin.")
    if username == actor:
        raise UserError("You cannot change your own role.")
    users = list_users(client)
    target = next((u for u in users if u["username"] == username), None)
    if not target:
        raise UserError("That user does not exist.")
    if target["role"] == "admin" and role != "admin":
        _require_other_admin_remains(users, username)
    for group in ROLES:
        if group != role:
            try:
                client.admin_remove_user_from_group(UserPoolId=pool_id(), Username=username, GroupName=group)
            except client.exceptions.ClientError:
                pass
    client.admin_add_user_to_group(UserPoolId=pool_id(), Username=username, GroupName=role)
    _audit(conn, "USER_ROLE_CHANGED", actor, username=username, old_role=target["role"], new_role=role)


def set_enabled(conn, username, enabled, actor, client=None):
    client = client or _client()
    if username == actor:
        raise UserError("You cannot disable your own account.")
    users = list_users(client)
    target = next((u for u in users if u["username"] == username), None)
    if not target:
        raise UserError("That user does not exist.")
    if not enabled and target["role"] == "admin":
        _require_other_admin_remains(users, username)
    (client.admin_enable_user if enabled else client.admin_disable_user)(UserPoolId=pool_id(), Username=username)
    _audit(conn, "USER_ENABLED" if enabled else "USER_DISABLED", actor, username=username)


def delete_user(conn, username, actor, client=None):
    client = client or _client()
    if username == actor:
        raise UserError("You cannot delete your own account.")
    users = list_users(client)
    target = next((u for u in users if u["username"] == username), None)
    if not target:
        raise UserError("That user does not exist.")
    if target["role"] == "admin":
        _require_other_admin_remains(users, username)
    client.admin_delete_user(UserPoolId=pool_id(), Username=username)
    _audit(conn, "USER_DELETED", actor, username=username)


def resend_invitation(conn, username, actor, client=None):
    client = client or _client()
    users = list_users(client)
    target = next((u for u in users if u["username"] == username), None)
    if not target:
        raise UserError("That user does not exist.")
    if target["status"] != "FORCE_CHANGE_PASSWORD":
        raise UserError("Only users who have not signed in yet can be re-invited.")
    client.admin_create_user(UserPoolId=pool_id(), Username=username, MessageAction="RESEND", DesiredDeliveryMediums=["EMAIL"])
    _audit(conn, "USER_REINVITED", actor, username=username)


def local_users() -> list:
    """Development logins from POLICYGUARD_LOCAL_USERS; shown read-only."""
    users = []
    for entry in filter(None, os.environ.get("POLICYGUARD_LOCAL_USERS", "").split(";")):
        name, _, rest = entry.partition(":")
        _stored, _, role = rest.rpartition(":")
        users.append({"username": name, "email": None, "status": "LOCAL", "enabled": True, "role": role, "created": None})
    return users
