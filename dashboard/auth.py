"""Login, sessions and role checks for the dashboard.

POLICYGUARD_AUTH selects the mode:
  off      (default) no login; for unit tests and quick local demos
  local    users from POLICYGUARD_LOCAL_USERS="name:password:role;..." (development only)
  cognito  Amazon Cognito user pool via USER_PASSWORD_AUTH (production on AWS)

Roles, lowest to highest: viewer < auditor < admin. Cognito groups with those names decide the role.
The session is a signed cookie; state-changing requests also need a CSRF token.
"""
import base64
import hmac
import json
import os
import secrets
import time
from functools import wraps

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request, session, url_for

ROLES = ("viewer", "auditor", "admin")
auth_bp = Blueprint("auth", __name__)

PUBLIC_ENDPOINTS = {"auth.login", "auth.new_password", "health", "static"}
# Minimum role per endpoint; anything not listed needs just a valid login (viewer).
ENDPOINT_ROLES = {
    "audit": "auditor", "audit_log.audit_log": "auditor", "violations.finding_evidence": "auditor",
    "scan_now": "admin", "reports": "auditor", "insight.export_csv": "auditor",
    "insight.export_bundle": "auditor", "insight.saved_reports": "auditor", "insight.printable_report": "auditor",
    "account_api.connect": "admin", "account_api.switch": "admin", "account_api.disconnect": "admin",
    "account_api.use_default": "admin",
}

_failures = {}  # ip -> [timestamps]; per process, a brake against guessing, not a full defence
MAX_FAILURES, WINDOW_SECONDS = 5, 300


def auth_mode() -> str:
    return os.environ.get("POLICYGUARD_AUTH", "off").lower()


def role_at_least(role: str, minimum: str) -> bool:
    return role in ROLES and ROLES.index(role) >= ROLES.index(minimum)


def current_user():
    if auth_mode() == "off":
        return {"username": "local", "role": "admin", "auth": "off"}
    return session.get("user")


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def _rate_limited(ip: str) -> bool:
    now = time.time()
    recent = [t for t in _failures.get(ip, []) if now - t < WINDOW_SECONDS]
    _failures[ip] = recent
    return len(recent) >= MAX_FAILURES


def _register_failure(ip: str):
    _failures.setdefault(ip, []).append(time.time())


def _role_from_groups(groups) -> str:
    best = "viewer"
    for group in groups or []:
        if group in ROLES and ROLES.index(group) > ROLES.index(best):
            best = group
    return best


def _jwt_claims(token: str) -> dict:
    """Read claims from a token Cognito just handed us over TLS. It is not accepted from the client,
    so signature verification would add nothing here."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode()))


def _cognito_client():
    import boto3
    return boto3.client("cognito-idp", region_name=os.environ.get("COGNITO_REGION") or os.environ.get("AWS_REGION"))


def _user_from_tokens(username, result):
    claims = _jwt_claims(result["IdToken"])
    return {"username": claims.get("cognito:username") or claims.get("email") or username,
            "email": claims.get("email"), "role": _role_from_groups(claims.get("cognito:groups")), "auth": "cognito"}


def _authenticate_local(username, password):
    for entry in filter(None, os.environ.get("POLICYGUARD_LOCAL_USERS", "").split(";")):
        name, _, rest = entry.partition(":")
        stored, _, role = rest.rpartition(":")
        if hmac.compare_digest(name, username) and hmac.compare_digest(stored, password) and role in ROLES:
            return {"username": name, "role": role, "auth": "local"}
    return None


def _authenticate_cognito(username, password):
    """Returns (user, None), (None, challenge) or (None, None) when credentials are wrong."""
    client = _cognito_client()
    try:
        response = client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH", ClientId=os.environ["COGNITO_CLIENT_ID"],
            AuthParameters={"USERNAME": username, "PASSWORD": password})
    except client.exceptions.NotAuthorizedException:
        return None, None
    except client.exceptions.UserNotFoundException:
        return None, None
    if response.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
        return None, {"session": response["Session"], "username": username}
    return _user_from_tokens(username, response["AuthenticationResult"]), None


def _start_session(user):
    session.clear()
    session["user"] = user
    session.permanent = True
    csrf_token()


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None, mode=auth_mode(), csrf=csrf_token(),
                               challenge=bool(session.get("challenge")))
    if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
        return render_template("login.html", error="Session expired. Please try again.", mode=auth_mode(),
                               csrf=csrf_token(), challenge=False), 400
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
    if _rate_limited(ip):
        return render_template("login.html", error="Too many failed attempts. Wait a few minutes.",
                               mode=auth_mode(), csrf=csrf_token(), challenge=False), 429
    username, password = request.form.get("username", "").strip(), request.form.get("password", "")
    user, challenge = None, None
    if auth_mode() == "local":
        user = _authenticate_local(username, password)
    elif auth_mode() == "cognito":
        user, challenge = _authenticate_cognito(username, password)
    if challenge:
        session["challenge"] = challenge
        return render_template("login.html", error=None, mode=auth_mode(), csrf=csrf_token(), challenge=True)
    if not user:
        _register_failure(ip)
        return render_template("login.html", error="Incorrect username or password.", mode=auth_mode(),
                               csrf=csrf_token(), challenge=False, username=username), 401
    _start_session(user)
    return redirect(url_for("index"))


@auth_bp.route("/login/new-password", methods=["POST"])
def new_password():
    """Cognito admin-created users must choose a permanent password on first sign-in."""
    challenge = session.get("challenge")
    if not challenge or not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
        return redirect(url_for("auth.login"))
    client = _cognito_client()
    try:
        response = client.respond_to_auth_challenge(
            ClientId=os.environ["COGNITO_CLIENT_ID"], ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=challenge["session"],
            ChallengeResponses={"USERNAME": challenge["username"], "NEW_PASSWORD": request.form.get("password", "")})
    except client.exceptions.InvalidPasswordException as error:
        return render_template("login.html", error=str(error), mode=auth_mode(), csrf=csrf_token(), challenge=True), 400
    except Exception:
        session.pop("challenge", None)
        return render_template("login.html", error="Could not set the password. Sign in again.", mode=auth_mode(),
                               csrf=csrf_token(), challenge=False), 400
    _start_session(_user_from_tokens(challenge["username"], response["AuthenticationResult"]))
    return redirect(url_for("index"))


@auth_bp.route("/logout", methods=["POST"])
def logout():
    if not hmac.compare_digest(request.form.get("csrf", request.headers.get("X-CSRF-Token", "")), session.get("csrf", "x")):
        abort(400)
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/api/me")
def me():
    user = current_user()
    return jsonify({"username": user["username"], "role": user["role"], "auth": user.get("auth"),
                    "csrf": csrf_token() if auth_mode() != "off" else None})


def require_role(minimum):
    """Decorator for routes that need more than the default viewer role."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                abort(401)
            if not role_at_least(user["role"], minimum):
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def init_auth(app):
    app.secret_key = os.environ.get("POLICYGUARD_SECRET_KEY") or secrets.token_hex(32)
    if auth_mode() != "off" and not os.environ.get("POLICYGUARD_SECRET_KEY"):
        # A per-process random key means two servers would not accept each other's cookies.
        app.logger.warning("POLICYGUARD_SECRET_KEY is not set; sessions will not be shared between instances")
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("POLICYGUARD_COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=int(os.environ.get("POLICYGUARD_SESSION_SECONDS", "28800")))
    app.register_blueprint(auth_bp)

    @app.before_request
    def enforce_login():
        if auth_mode() == "off" or request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
            return None
        user = session.get("user")
        if not user:
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("auth.login"))
        minimum = ENDPOINT_ROLES.get(request.endpoint, "viewer")
        if not role_at_least(user["role"], minimum):
            if request.path.startswith("/api/"):
                return jsonify({"error": f"requires {minimum} role"}), 403
            return render_template("forbidden.html", needed=minimum, title="Access denied", page="forbidden"), 403
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf", "")
            if not hmac.compare_digest(supplied, session.get("csrf", "x")):
                return jsonify({"error": "missing or invalid CSRF token"}), 400
        return None

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        if request.path.startswith("/api/") or request.endpoint == "auth.login":
            response.headers["Cache-Control"] = "no-store"
        return response
