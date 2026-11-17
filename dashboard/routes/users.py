"""Admin-only user management API (Cognito)."""
from flask import Blueprint, jsonify, request

from dashboard import users
from dashboard.auth import current_user
from db.store import connect

users_bp = Blueprint("users_api", __name__)


def _actor():
    return (current_user() or {}).get("username", "unknown")


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _snapshot():
    if users.managed():
        return {"managed": True, "mode": "cognito", "roles": list(users.ROLES), "users": users.list_users(),
                "me": _actor()}
    return {"managed": False, "mode": "local", "roles": list(users.ROLES), "users": users.local_users(), "me": _actor(),
            "note": "Users are managed in Cognito on the AWS deployment. These are development logins from the environment."}


def _act(fn):
    if not users.managed():
        return jsonify({"error": "User management needs the Cognito login used on the AWS deployment."}), 400
    conn = connect()
    try:
        fn(conn)
        return jsonify(_snapshot())
    except users.UserError as error:
        return jsonify({"error": str(error)}), 400
    finally:
        conn.close()


@users_bp.route("/api/users")
def list_all():
    try:
        return jsonify(_snapshot())
    except Exception as error:
        return jsonify({"error": f"Could not read the user pool: {error}"}), 502


@users_bp.route("/api/users", methods=["POST"])
def create():
    data = _body()
    return _act(lambda conn: users.create_user(conn, data.get("username"), data.get("email"), data.get("role"), _actor()))


@users_bp.route("/api/users/<username>/role", methods=["POST"])
def role(username):
    data = _body()
    return _act(lambda conn: users.set_role(conn, username, data.get("role"), _actor()))


@users_bp.route("/api/users/<username>/enable", methods=["POST"])
def enable(username):
    return _act(lambda conn: users.set_enabled(conn, username, True, _actor()))


@users_bp.route("/api/users/<username>/disable", methods=["POST"])
def disable(username):
    return _act(lambda conn: users.set_enabled(conn, username, False, _actor()))


@users_bp.route("/api/users/<username>/delete", methods=["POST"])
def delete(username):
    return _act(lambda conn: users.delete_user(conn, username, _actor()))


@users_bp.route("/api/users/<username>/resend", methods=["POST"])
def resend(username):
    return _act(lambda conn: users.resend_invitation(conn, username, _actor()))
