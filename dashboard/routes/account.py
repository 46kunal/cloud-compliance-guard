"""API for seeing and changing the monitored AWS account. Mutating calls are admin-only (see auth.ENDPOINT_ROLES)
and CSRF-protected; credentials are never logged, stored or returned."""
from flask import Blueprint, jsonify, request

from dashboard import account
from dashboard.auth import auth_mode

account_api = Blueprint("account_api", __name__)

REGIONS = [
    ("ap-south-1", "Asia Pacific (Mumbai)"), ("ap-south-2", "Asia Pacific (Hyderabad)"),
    ("us-east-1", "US East (N. Virginia)"), ("us-east-2", "US East (Ohio)"), ("us-west-2", "US West (Oregon)"),
    ("eu-west-1", "Europe (Ireland)"), ("eu-central-1", "Europe (Frankfurt)"),
    ("ap-southeast-1", "Asia Pacific (Singapore)"), ("ap-northeast-1", "Asia Pacific (Tokyo)"),
]


def _snapshot():
    reason = account.switching_block_reason()
    return {"current": account.current(), "connections": account.connections(),
            "switching": {"allowed": reason is None, "reason": reason},
            "regions": [{"id": rid, "name": name} for rid, name in REGIONS]}


def _refuse_remote_when_unauthenticated():
    # With sign-in off the dashboard is for local use; never let another machine change credentials.
    if auth_mode() == "off" and request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"error": "Sign-in is off, so the monitored account can only be changed from this computer."}), 403
    return None


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _run(action):
    refused = _refuse_remote_when_unauthenticated()
    if refused:
        return refused
    try:
        action()
    except account.AccountError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify(_snapshot())


@account_api.route("/api/account")
def get_account():
    return jsonify(_snapshot())


@account_api.route("/api/account/connect", methods=["POST"])
def connect():
    data = _body()
    return _run(lambda: account.connect(data.get("access_key_id"), data.get("secret_access_key"),
                                        data.get("session_token"), data.get("region")))


@account_api.route("/api/account/switch", methods=["POST"])
def switch():
    data = _body()
    return _run(lambda: account.switch(str(data.get("account_id") or "")))


@account_api.route("/api/account/disconnect", methods=["POST"])
def disconnect():
    data = _body()
    return _run(lambda: account.disconnect(str(data.get("account_id") or "") or None))


@account_api.route("/api/account/default", methods=["POST"])
def use_default():
    return _run(account.use_default)
