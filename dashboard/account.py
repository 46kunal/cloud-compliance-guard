"""Which AWS account PolicyGuard monitors right now, and switching between accounts.

Three states:
  default  the AWS credentials this process already has (environment, ~/.aws or an IAM role)
  session  access keys an admin typed into the dashboard
  none     disconnected: scans are refused until an account is connected again

Keys typed into the dashboard live only in this process's memory. They are never written to disk, the
database, logs or API responses, and they are forgotten when the server restarts. On the AWS deployment the
account is fixed by the scanner's IAM role, so switching is turned off there.
"""
import os
import re
import threading
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Shared with the scanner: the account is never changed while a scan is running.
scan_lock = threading.Lock()
_lock = threading.RLock()
_connections = {}          # account_id -> record that includes the secret; never returned to callers
_state = {"mode": "default", "account_id": None}
_ORIGINAL_REGION = os.environ.get("AWS_DEFAULT_REGION")
_identity_cache = {"at": 0.0, "value": None}
IDENTITY_TTL_SECONDS = 60
LOCK_WAIT_SECONDS = 8

ACCESS_KEY = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
SECRET_KEY = re.compile(r"^[A-Za-z0-9/+=]{40}$")
REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")

SOURCE_LABELS = {
    "shared-credentials-file": "AWS credentials file on this computer",
    "env": "Environment variables",
    "iam-role": "IAM role (instance profile)",
    "container-role": "IAM role (container)",
    "assume-role": "Assumed IAM role",
    "sso": "AWS IAM Identity Center (SSO)",
    "config-file": "AWS config file on this computer",
}


class AccountError(Exception):
    """A problem with a user-supplied account; the message is safe to show in the UI."""


class NoAccountConnected(AccountError):
    pass


def switching_block_reason():
    """None when an admin may change the monitored account, otherwise why not."""
    if os.environ.get("POLICYGUARD_BACKEND", "sqlite").lower() == "dynamodb" or os.environ.get("POLICYGUARD_SCANNER_FUNCTION"):
        return "On the AWS deployment the monitored account is fixed by the scanner's IAM role."
    if os.environ.get("POLICYGUARD_ACCOUNT_ID") or os.environ.get("POLICYGUARD_ACCOUNT_SCOPE"):
        return "The monitored account is pinned by POLICYGUARD_ACCOUNT_ID."
    if os.environ.get("POLICYGUARD_ALLOW_ACCOUNT_SWITCH", "true").lower() == "false":
        return "Account switching is turned off (POLICYGUARD_ALLOW_ACCOUNT_SWITCH=false)."
    return None


def _caller_identity(**credentials):
    """STS identity for the given credentials, or for the process default when none are given."""
    return boto3.client("sts", **credentials).get_caller_identity()


def _region():
    # AWS_REGION is what the EC2 servers set; boto3 itself only reads AWS_DEFAULT_REGION or the config file.
    return boto3.session.Session().region_name or os.environ.get("AWS_REGION") or "us-east-1"


def _credential_source():
    credentials = boto3.Session().get_credentials()
    method = getattr(credentials, "method", None)
    return SOURCE_LABELS.get(method, method or "Unknown")


def _default_identity():
    """Identity of the ambient credentials, cached briefly so every page load does not call AWS."""
    now = time.time()
    with _lock:
        if now - _identity_cache["at"] < IDENTITY_TTL_SECONDS:
            return _identity_cache["value"]
    try:
        value = _caller_identity()
    except Exception:
        value = None
    with _lock:
        _identity_cache.update(at=now, value=value)
    return value


def _reset_default_session():
    """Forget any keys loaded into boto3's default session and fall back to the ambient credentials."""
    boto3.setup_default_session()
    if _ORIGINAL_REGION is None:
        os.environ.pop("AWS_DEFAULT_REGION", None)
    else:
        os.environ["AWS_DEFAULT_REGION"] = _ORIGINAL_REGION
    _identity_cache["at"] = 0.0


def _activate(account_id):
    record = _connections[account_id]
    boto3.setup_default_session(
        aws_access_key_id=record["access_key_id"], aws_secret_access_key=record["secret"],
        aws_session_token=record["token"], region_name=record["region"])
    os.environ["AWS_DEFAULT_REGION"] = record["region"]
    _state.update(mode="session", account_id=account_id)
    _identity_cache["at"] = 0.0


def current():
    """What the dashboard is monitoring right now. Never includes a secret."""
    with _lock:
        mode, active = _state["mode"], _state["account_id"]
        record = _connections.get(active) if mode == "session" else None
    if mode == "none":
        return {"state": "none", "connected": False, "account_id": None, "arn": None, "region": _region(),
                "source": None, "message": "No AWS account is connected. Scans are paused."}
    if record:
        return {"state": "session", "connected": True, "account_id": active, "arn": record["arn"],
                "region": record["region"], "source": "Access keys entered in this dashboard",
                "key_hint": "…" + record["access_key_id"][-4:], "message": None}
    identity = _default_identity()
    if identity is None:
        return {"state": "default", "connected": False, "account_id": None, "arn": None, "region": _region(),
                "source": _credential_source(), "message": "No working AWS credentials were found."}
    return {"state": "default", "connected": True, "account_id": identity["Account"], "arn": identity["Arn"],
            "region": _region(), "source": _credential_source(), "message": None}


def connections():
    with _lock:
        active = _state["account_id"] if _state["mode"] == "session" else None
        return [{"account_id": account_id, "arn": record["arn"], "region": record["region"],
                 "key_hint": "…" + record["access_key_id"][-4:], "connected_at": record["connected_at"],
                 "active": account_id == active} for account_id, record in _connections.items()]


def active_account_id():
    """Account id of whatever is being monitored, or None when disconnected or unidentifiable."""
    with _lock:
        mode, active = _state["mode"], _state["account_id"]
    if mode == "none":
        return None
    if mode == "session":
        return active
    identity = _default_identity()
    return identity["Account"] if identity else None


def ensure_can_scan():
    if _state["mode"] == "none":
        raise NoAccountConnected("No AWS account is connected. Connect one on the AWS account page.")


def _take_scan_lock():
    if not scan_lock.acquire(timeout=LOCK_WAIT_SECONDS):
        raise AccountError("A scan is running right now. Try again in a moment.")


def _require_switching():
    reason = switching_block_reason()
    if reason:
        raise AccountError(reason)


def connect(access_key_id, secret_access_key, session_token=None, region=None):
    """Verify the keys with AWS, then monitor that account. Raises AccountError with a safe message."""
    _require_switching()
    key = (access_key_id or "").strip()
    secret = (secret_access_key or "").strip()
    token = (session_token or "").strip() or None
    region = (region or "").strip() or None
    if not ACCESS_KEY.match(key):
        raise AccountError("The access key ID looks wrong. It has 20 characters and starts with AKIA (or ASIA for temporary keys).")
    if not SECRET_KEY.match(secret):
        raise AccountError("The secret access key looks wrong. It has 40 characters.")
    if key.startswith("ASIA") and not token:
        raise AccountError("Temporary (ASIA) keys also need a session token.")
    if region and not REGION.match(region):
        raise AccountError("The region looks wrong. Use a name like ap-south-1.")
    region = region or _region()

    try:
        identity = _caller_identity(aws_access_key_id=key, aws_secret_access_key=secret,
                                    aws_session_token=token, region_name=region)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code in ("InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken", "InvalidToken", "AccessDenied"):
            raise AccountError("AWS rejected these credentials. Check the keys, and that they are still active.")
        raise AccountError("AWS could not verify these credentials (" + (code or "unknown error") + ").")
    except BotoCoreError:
        raise AccountError("Could not reach AWS to verify the credentials. Check the network and try again.")

    _take_scan_lock()
    try:
        with _lock:
            account_id = identity["Account"]
            _connections[account_id] = {
                "access_key_id": key, "secret": secret, "token": token, "region": region, "arn": identity["Arn"],
                "connected_at": datetime.now(timezone.utc).isoformat()}
            _activate(account_id)
    finally:
        scan_lock.release()
    return current()


def switch(account_id):
    _require_switching()
    with _lock:
        known = account_id in _connections
    if not known:
        raise AccountError("That account is not connected. Connect it with its access keys first.")
    _take_scan_lock()
    try:
        with _lock:
            _activate(account_id)
    finally:
        scan_lock.release()
    return current()


def disconnect(account_id=None):
    """Stop monitoring an account and forget its keys. With no id, disconnects whatever is active."""
    _require_switching()
    _take_scan_lock()
    try:
        with _lock:
            active = _state["account_id"] if _state["mode"] == "session" else None
            if account_id and account_id != active:
                _connections.pop(account_id, None)     # a stored but inactive account: just forget its keys
                return current()
            _connections.pop(active, None)
            _reset_default_session()
            _state.update(mode="none", account_id=None)
    finally:
        scan_lock.release()
    return current()


def use_default():
    """Go back to the credentials the process started with (environment, ~/.aws or an IAM role)."""
    _require_switching()
    _take_scan_lock()
    try:
        with _lock:
            _reset_default_session()
            _state.update(mode="default", account_id=None)
    finally:
        scan_lock.release()
    return current()


def visible_scope(conn):
    """Account whose data the dashboard should show.

    None means "show everything": the database only knows one account, or the active account cannot be
    identified. Once two or more accounts have been scanned, the views follow the active account.
    """
    from db.store import get_scans
    scopes = {scan.get("account_scope") for scan in get_scans(conn, 500)} - {None, "legacy"}
    if len(scopes) <= 1:
        return None
    try:
        from flask import has_request_context, session
        chosen = session.get("view_account") if has_request_context() else None
    except Exception:
        chosen = None
    if chosen == "ALL":
        return None
    if chosen in scopes:
        return chosen
    return active_account_id()


def in_scope(items, scope, key="account_scope"):
    return items if scope is None else [item for item in items if item.get(key) == scope]


def latest_scan_in_scope(conn, scope):
    from db.store import get_latest_scan, get_scans
    if scope is None:
        return get_latest_scan(conn)
    return next((scan for scan in get_scans(conn, 500) if scan.get("account_scope") == scope), None)


def reset_for_tests():
    with _lock:
        _connections.clear()
        _state.update(mode="default", account_id=None)
        _reset_default_session()
