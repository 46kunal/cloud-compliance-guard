"""
Creates (or deletes) intentionally misconfigured resources in YOUR AWS account so
PolicyGuard has real violations to detect — all visible in the AWS console.

    python infra/demo_resources.py create
    python infra/demo_resources.py delete

Creates (all prefixed "policyguard-demo"):
  - S3 bucket with a public-read bucket policy           -> public_storage (HIGH, PRIVACY tier)
  - Customer-managed IAM policy Allow * on *             -> wildcard_permission (HIGH, SECURITY tier)
    attached to an IAM role only this account can assume (no one outside gets access)
  - IAM user with console password and no MFA            -> mfa_required (MEDIUM, SECURITY tier)
    (random password, never printed — nobody can log in as it)

Use a sandbox/student account. The public bucket is empty, but it IS publicly readable
until you run "delete" or PolicyGuard remediates it.
"""
import json
import secrets
import sys

import boto3

PREFIX = "policyguard-demo"
POLICY_NAME = f"{PREFIX}-admin-wildcard"
ROLE_NAME = f"{PREFIX}-role"
USER_NAME = f"{PREFIX}-user"
READONLY_POLICY_NAME = f"{PREFIX}-readonly"


def _private_bucket(account: str) -> str:
    return f"{PREFIX}-private-{account}"


def _names():
    account = boto3.client("sts").get_caller_identity()["Account"]
    region = boto3.session.Session().region_name or "us-east-1"
    return account, region, f"{PREFIX}-public-{account}"


def create():
    account, region, bucket = _names()
    s3, iam = boto3.client("s3", region_name=region), boto3.client("iam")

    kwargs = {} if region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": region}}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": False, "IgnorePublicAcls": False,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": False})

    # Tag public bucket for Tier 1 Privacy (DPDP Act 2023)
    try:
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
            {"Key": "data-type", "Value": "user-records"},
            {"Key": "handles_personal_data", "Value": "true"}
        ]})
    except Exception as e:
        print(f"[CREATE] Warning tagging public bucket {bucket}: {e}")

    try:
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*"}]}))
        print(f"[CREATE] Public bucket          s3://{bucket}")
    except Exception as e:
        print(f"[CREATE] Bucket s3://{bucket} created, but public policy was refused: {e}")
        print("         Account-level Block Public Access is on: S3 console > Block Public Access settings for this account.")

    # Create wildcard IAM policy and role (Security tier)
    policy_arn = f"arn:aws:iam::{account}:policy/{POLICY_NAME}"
    try:
        policy_res = iam.create_policy(
            PolicyName=POLICY_NAME,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
            Tags=[{"Key": "handles_personal_data", "Value": "false"}]
        )
        policy_arn = policy_res["Policy"]["Arn"]
    except Exception:
        pass

    try:
        iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}}]}),
            Tags=[{"Key": "handles_personal_data", "Value": "false"}]
        )
    except Exception:
        pass

    try:
        iam.attach_role_policy(RoleName=ROLE_NAME, PolicyArn=policy_arn)
    except Exception:
        pass

    print(f"[CREATE] Wildcard IAM policy    {policy_arn} (attached to role {ROLE_NAME})")

    # Create user without MFA (Security tier)
    try:
        iam.create_user(UserName=USER_NAME, Tags=[{"Key": "handles_personal_data", "Value": "false"}])
    except Exception:
        pass
    try:
        iam.create_login_profile(UserName=USER_NAME, Password=secrets.token_urlsafe(24) + "aA1!")
    except Exception:
        pass
    print(f"[CREATE] IAM user without MFA   {USER_NAME}")

    # Correctly configured resources (compliant private bucket tagged handles_personal_data=true)
    private = _private_bucket(account)
    s3.create_bucket(Bucket=private, **kwargs)
    s3.put_public_access_block(Bucket=private, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_encryption(Bucket=private, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    try:
        s3.put_bucket_tagging(Bucket=private, Tagging={"TagSet": [
            {"Key": "data-type", "Value": "user-records"},
            {"Key": "handles_personal_data", "Value": "true"}
        ]})
    except Exception as e:
        print(f"[CREATE] Warning tagging private bucket {private}: {e}")

    print(f"[CREATE] Compliant bucket       s3://{private}")

    try:
        iam.create_policy(PolicyName=READONLY_POLICY_NAME, PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                                                    "Resource": f"arn:aws:s3:::{private}/*"}]}))
    except Exception:
        pass
    print(f"[CREATE] Least-privilege policy {READONLY_POLICY_NAME}")

    print()
    print("Allowlist these for a live remediation demo (lambdas/remediation/safety/allowlist.json):")
    print(json.dumps({"allowed_resource_ids": [bucket, policy_arn]}, indent=2))


def _ignore_missing(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception as e:
        if "NoSuch" not in str(e) and "NotFound" not in str(e):
            print(f"[DELETE] warning: {e}")


def delete():
    account, region, bucket = _names()
    s3, iam = boto3.client("s3", region_name=region), boto3.client("iam")
    policy_arn = f"arn:aws:iam::{account}:policy/{POLICY_NAME}"

    _ignore_missing(s3.delete_bucket_policy, Bucket=bucket)
    _ignore_missing(s3.delete_bucket_tagging, Bucket=bucket)
    _ignore_missing(s3.delete_bucket, Bucket=bucket)
    _ignore_missing(iam.detach_role_policy, RoleName=ROLE_NAME, PolicyArn=policy_arn)
    _ignore_missing(iam.delete_role, RoleName=ROLE_NAME)
    _ignore_missing(iam.delete_policy, PolicyArn=policy_arn)
    _ignore_missing(iam.delete_login_profile, UserName=USER_NAME)
    _ignore_missing(iam.delete_user, UserName=USER_NAME)
    _ignore_missing(s3.delete_bucket_tagging, Bucket=_private_bucket(account))
    _ignore_missing(s3.delete_bucket, Bucket=_private_bucket(account))
    _ignore_missing(iam.delete_policy, PolicyArn=f"arn:aws:iam::{account}:policy/{READONLY_POLICY_NAME}")
    print("[DELETE] Demo resources removed.")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "create":
        create()
    elif command == "delete":
        delete()
    else:
        sys.exit("usage: python infra/demo_resources.py create|delete")
