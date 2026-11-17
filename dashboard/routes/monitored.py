"""Monitored accounts (cross-account roles) and the 'which account am I viewing' selector."""
import os

from flask import Blueprint, Response, jsonify, request, session

from dashboard import monitored
from dashboard.auth import current_user
from db.store import connect, get_scans

monitored_bp = Blueprint("monitored", __name__)


def _actor():
    user = current_user() or {}
    return user.get("username", "unknown")


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _with_conn(fn):
    conn = connect()
    try:
        return fn(conn)
    finally:
        conn.close()


def _snapshot(conn):
    home = None
    try:
        home = monitored.home_account_id()
    except Exception:
        pass
    return {"home_account_id": home, "accounts": [monitored.public_view(a) for a in monitored.list_accounts(conn)],
            "role_name": monitored.ROLE_NAME,
            "scan_function": os.environ.get("POLICYGUARD_SCANNER_FUNCTION")}


@monitored_bp.route("/api/monitored-accounts")
def list_accounts():
    return jsonify(_with_conn(_snapshot))


@monitored_bp.route("/api/monitored-accounts", methods=["POST"])
def create_account():
    data = _body()

    def run(conn):
        account = monitored.create(conn, data.get("name"), data.get("account_id"), data.get("region"), _actor())
        return {**_snapshot(conn), "instructions": monitored.instructions(account)}
    try:
        return jsonify(_with_conn(run)), 201
    except monitored.AccountError as error:
        return jsonify({"error": str(error)}), 400


@monitored_bp.route("/api/monitored-accounts/<account_id>/instructions")
def account_instructions(account_id):
    account = _with_conn(lambda conn: monitored.get_account(conn, account_id))
    if not account:
        return jsonify({"error": "That account is not registered."}), 404
    return jsonify(monitored.instructions(account))


@monitored_bp.route("/api/monitored-accounts/<account_id>/template")
def account_template(account_id):
    account = _with_conn(lambda conn: monitored.get_account(conn, account_id))
    if not account:
        return jsonify({"error": "That account is not registered."}), 404
    path = os.path.join(os.path.dirname(__file__), "..", "..", "infra", "cloudformation", "member-account-role.yaml")
    with open(os.path.abspath(path), encoding="utf-8") as handle:
        return Response(handle.read(), mimetype="text/yaml",
                        headers={"Content-Disposition": "attachment; filename=member-account-role.yaml"})


def _act(account_id, fn):
    def run(conn):
        fn(conn)
        return _snapshot(conn)
    try:
        return jsonify(_with_conn(run))
    except monitored.AccountError as error:
        return jsonify({"error": str(error)}), 400


@monitored_bp.route("/api/monitored-accounts/<account_id>/verify", methods=["POST"])
def verify_account(account_id):
    return _act(account_id, lambda conn: monitored.verify(conn, account_id, _actor()))


@monitored_bp.route("/api/monitored-accounts/<account_id>/enable", methods=["POST"])
def enable_account(account_id):
    return _act(account_id, lambda conn: monitored.set_enabled(conn, account_id, True, _actor()))


@monitored_bp.route("/api/monitored-accounts/<account_id>/disable", methods=["POST"])
def disable_account(account_id):
    return _act(account_id, lambda conn: monitored.set_enabled(conn, account_id, False, _actor()))


@monitored_bp.route("/api/monitored-accounts/<account_id>/delete", methods=["POST"])
def delete_account(account_id):
    return _act(account_id, lambda conn: monitored.remove(conn, account_id, _actor()))


@monitored_bp.route("/api/monitored-accounts/<account_id>/scan", methods=["POST"])
def scan_account(account_id):
    function = os.environ.get("POLICYGUARD_SCANNER_FUNCTION")
    if not function:
        return jsonify({"error": "Scanning a member account needs the scheduled scanner (AWS deployment)."}), 400
    account = _with_conn(lambda conn: monitored.get_account(conn, account_id))
    if not account or not account.get("enabled"):
        return jsonify({"error": "That account is not enabled. Verify it first."}), 400
    import json
    import boto3
    response = boto3.client("lambda").invoke(FunctionName=function, InvocationType="RequestResponse",
                                             Payload=json.dumps({"account_id": account_id}).encode())
    payload = json.loads(response["Payload"].read() or b"{}")
    if response.get("FunctionError"):
        return jsonify({"error": "Scan failed", "detail": payload.get("errorMessage", "")}), 500
    return jsonify(payload)


# ---- which account's data the pages show ----
def view_options(conn):
    names = {a["account_id"]: a["name"] for a in monitored.list_accounts(conn)}
    scopes = []
    for scan in get_scans(conn, 500):
        scope = scan.get("account_scope")
        if scope and scope != "legacy" and scope not in scopes:
            scopes.append(scope)
    home = None
    try:
        home = monitored.home_account_id()
    except Exception:
        pass
    if home in scopes:
        scopes.remove(home)
        scopes.insert(0, home)
    options = [{"id": s, "label": (names.get(s) + " · " if names.get(s) else ("This account · " if s == home else "")) + s}
               for s in scopes]
    if len(options) > 1:
        options.append({"id": "ALL", "label": "All accounts"})
    return options, home


@monitored_bp.route("/api/view")
def get_view():
    options, home = _with_conn(view_options)
    chosen = session.get("view_account")
    valid = {o["id"] for o in options}
    current = chosen if chosen in valid else (options[0]["id"] if options else None)
    return jsonify({"options": options, "current": current})


@monitored_bp.route("/api/view", methods=["POST"])
def set_view():
    options, _home = _with_conn(view_options)
    chosen = str(_body().get("account_id") or "")
    if chosen not in {o["id"] for o in options}:
        return jsonify({"error": "Unknown account."}), 400
    session["view_account"] = chosen
    return jsonify({"current": chosen})
