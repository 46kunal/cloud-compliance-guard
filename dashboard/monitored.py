"""Monitored AWS accounts reached through cross-account IAM roles (no access keys are ever stored).

Adding an account is a handshake:
  1. An admin registers the account ID. PolicyGuard generates an External ID and shows a CloudFormation template.
  2. The owner of that account deploys the template, creating a read-only role named PolicyGuard* that trusts
     only PolicyGuard's own roles and only when the External ID matches (this stops the confused-deputy problem).
  3. The admin presses Verify. PolicyGuard calls sts:AssumeRole; on success the account becomes ACTIVE and is
     scanned with short-lived credentials on every scheduled run.

The account owner stays in control: deleting the role ends access immediately, and every assumption is in CloudTrail.
"""
import os
import re
import secrets
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

KIND = "accounts"
ACCOUNT_ID = re.compile(r"^\d{12}$")
REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")
ROLE_NAME = "PolicyGuardReadOnly"
SESSION_SECONDS = 900
STATES = ("PENDING", "ACTIVE")

_assume_lock = threading.Lock()


class AccountError(Exception):
    """A problem with a user-supplied account; the message is safe to show."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def role_arn(account_id: str, role_name: str = ROLE_NAME) -> str:
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def home_account_id() -> str:
    configured = os.environ.get("POLICYGUARD_HOME_ACCOUNT_ID")
    if configured:
        return configured
    import boto3
    return boto3.client("sts").get_caller_identity()["Account"]


def list_accounts(conn) -> list:
    from db.store import list_docs
    return sorted(list_docs(conn, KIND), key=lambda a: a.get("added_at", ""))


def get_account(conn, account_id: str):
    from db.store import get_doc
    return get_doc(conn, KIND, account_id)


def public_view(account: dict) -> dict:
    """What the UI may see. The external ID is shown to admins only, in the instructions."""
    keep = ("account_id", "name", "region", "role_arn", "status", "enabled", "added_by", "added_at", "verified_at",
            "last_error", "last_scan_at", "last_scan_status")
    return {key: account.get(key) for key in keep}


def create(conn, name: str, account_id: str, region: str, actor: str) -> dict:
    from db.store import append_audit_events, put_doc
    name, account_id, region = (name or "").strip(), (account_id or "").strip(), (region or "").strip() or "ap-south-1"
    if not name or len(name) > 60:
        raise AccountError("Give the account a short name (up to 60 characters).")
    if not ACCOUNT_ID.match(account_id):
        raise AccountError("The account ID must be exactly 12 digits.")
    if not REGION.match(region):
        raise AccountError("The region looks wrong. Use a name like ap-south-1.")
    if account_id == home_account_id():
        raise AccountError("That is the account PolicyGuard runs in. It is already monitored.")
    if get_account(conn, account_id):
        raise AccountError("That account is already registered.")
    account = {"account_id": account_id, "name": name, "region": region, "role_arn": role_arn(account_id),
               "external_id": secrets.token_urlsafe(24), "status": "PENDING", "enabled": False,
               "added_by": actor, "added_at": _now(), "verified_at": None, "last_error": None}
    put_doc(conn, KIND, account_id, account)
    append_audit_events(conn, [("ACCOUNT_REGISTERED", {"actor": actor, "account_id": account_id, "name": name})])
    return account


def _assume(account: dict) -> dict:
    import boto3
    sts = boto3.client("sts")
    response = sts.assume_role(RoleArn=account["role_arn"], RoleSessionName="policyguard-scan",
                               ExternalId=account["external_id"], DurationSeconds=SESSION_SECONDS)
    return response["Credentials"]


def verify(conn, account_id: str, actor: str) -> dict:
    from botocore.exceptions import BotoCoreError, ClientError
    from db.store import append_audit_events, put_doc
    account = get_account(conn, account_id)
    if not account:
        raise AccountError("That account is not registered.")
    try:
        _assume(account)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        reason = ("AWS refused the role. Check that the template was deployed in that account, that the role is "
                  "named PolicyGuard…, and that the External ID matches.") if code in ("AccessDenied", "AccessDeniedException") \
            else f"AWS could not assume the role ({code or 'unknown error'})."
        account.update(status="PENDING", enabled=False, last_error=reason)
        put_doc(conn, KIND, account_id, account)
        raise AccountError(reason)
    except BotoCoreError:
        raise AccountError("Could not reach AWS to verify the role. Try again.")
    account.update(status="ACTIVE", enabled=True, verified_at=_now(), last_error=None)
    put_doc(conn, KIND, account_id, account)
    append_audit_events(conn, [("ACCOUNT_VERIFIED", {"actor": actor, "account_id": account_id, "name": account["name"]})])
    return account


def set_enabled(conn, account_id: str, enabled: bool, actor: str) -> dict:
    from db.store import append_audit_events, put_doc
    account = get_account(conn, account_id)
    if not account:
        raise AccountError("That account is not registered.")
    if enabled and account.get("status") != "ACTIVE":
        raise AccountError("Verify the role first. Only verified accounts can be scanned.")
    account["enabled"] = bool(enabled)
    put_doc(conn, KIND, account_id, account)
    append_audit_events(conn, [("ACCOUNT_ENABLED" if enabled else "ACCOUNT_DISABLED",
                                {"actor": actor, "account_id": account_id})])
    return account


def remove(conn, account_id: str, actor: str) -> None:
    from db.store import append_audit_events, delete_doc
    if not get_account(conn, account_id):
        raise AccountError("That account is not registered.")
    delete_doc(conn, KIND, account_id)
    append_audit_events(conn, [("ACCOUNT_REMOVED", {"actor": actor, "account_id": account_id,
                                                    "note": "Stored findings for this account are kept."})])


def record_scan(conn, account_id: str, status: str, error: str = None) -> None:
    from db.store import put_doc
    account = get_account(conn, account_id)
    if account:
        account.update(last_scan_at=_now(), last_scan_status=status, last_error=error)
        put_doc(conn, KIND, account_id, account)


@contextmanager
def assumed_session(account: dict):
    """Scan the member account: default boto3 session and region point at short-lived assumed-role credentials.

    The process-wide default session is swapped, so this must not run concurrently with another scan
    (the scheduled Lambda scans accounts one after another)."""
    import boto3
    with _assume_lock:
        credentials = _assume(account)
        previous_region = os.environ.get("AWS_DEFAULT_REGION")
        boto3.setup_default_session(aws_access_key_id=credentials["AccessKeyId"],
                                    aws_secret_access_key=credentials["SecretAccessKey"],
                                    aws_session_token=credentials["SessionToken"], region_name=account["region"])
        os.environ["AWS_DEFAULT_REGION"] = account["region"]
        try:
            yield
        finally:
            boto3.setup_default_session()
            if previous_region is None:
                os.environ.pop("AWS_DEFAULT_REGION", None)
            else:
                os.environ["AWS_DEFAULT_REGION"] = previous_region


def trusted_role_arns() -> list:
    arns = [os.environ.get("POLICYGUARD_SCANNER_ROLE_ARN"), os.environ.get("POLICYGUARD_INSTANCE_ROLE_ARN")]
    arns = [a for a in arns if a]
    return arns or [f"arn:aws:iam::{home_account_id()}:root"]


def instructions(account: dict) -> dict:
    """What the owner of the member account must deploy. Contains the External ID, so admins only."""
    params = {"ExternalId": account["external_id"], "HomeAccountId": home_account_id(),
              "TrustedRoleArns": ",".join(trusted_role_arns()), "RoleName": ROLE_NAME}
    overrides = " ".join(f'"{k}={v}"' for k, v in params.items())
    command = ("aws cloudformation deploy --stack-name policyguard-readonly-role --template-file member-account-role.yaml "
               f"--capabilities CAPABILITY_NAMED_IAM --parameter-overrides {overrides}")
    return {"account_id": account["account_id"], "role_arn": account["role_arn"], "parameters": params,
            "deploy_command": command, "template_url": f"/api/monitored-accounts/{account['account_id']}/template"}
