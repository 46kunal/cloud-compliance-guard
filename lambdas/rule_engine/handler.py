import importlib
import importlib.util
import json
import os
import sys
import boto3

try:
    from lambdas.rule_engine.framework_mapping import RULE_TO_CLAUSE
except ModuleNotFoundError:
    try:
        from framework_mapping import RULE_TO_CLAUSE
    except ModuleNotFoundError:
        RULE_TO_CLAUSE = {
            "public_storage": "GDPR Article 32 — Security of Processing",
            "encryption_at_rest": "PCI-DSS Requirement 3 — Protect Stored Account Data",
            "wildcard_permission": "PCI-DSS Requirement 7 — Restrict Access by Business Need to Know",
            "mfa_required": "PCI-DSS Requirement 8.4 — Multi-Factor Authentication",
        }


def get_normalized_s3_resources() -> list:
    """
    Lists S3 buckets using boto3, checks policy status for each bucket,
    and returns a list of normalized resource dicts.
    """
    resources = []
    try:
        s3_client = boto3.client("s3")
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket.get("Name")
            if not bucket_name:
                continue

            is_public = False
            try:
                policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
                is_public = (
                    policy_status.get("PolicyStatus", {}).get("IsPublic", False)
                )
            except Exception:
                is_public = False

            # Public Access Block fully enabled overrides a public policy
            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)
                cfg = pab.get("PublicAccessBlockConfiguration", {})
                if cfg.get("BlockPublicPolicy") and cfg.get("RestrictPublicBuckets"):
                    is_public = False
            except Exception:
                pass

            encrypted = False
            try:
                enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
                encrypted = bool(
                    enc.get("ServerSideEncryptionConfiguration", {}).get("Rules")
                )
            except Exception:
                encrypted = False

            resources.append({
                "resource_type": "object_storage",
                "provider": "aws",
                "resource_id": bucket_name,
                "is_public": is_public,
                "encrypted": encrypted,
                "permissions": [],
                "tags": {},
            })
    except Exception as e:
        # Gracefully handle missing credentials or API errors
        pass

    return resources


def get_normalized_iam_resources() -> list:
    """
    Lists customer-managed IAM policies (as resource_type "iam_policy", with the
    default version's statements in "permissions") and IAM users (as resource_type
    "iam_user", with "has_console_access" / "mfa_enabled" flags).
    Returns [] on missing credentials or API errors, like the S3 collector.
    """
    resources = []
    try:
        iam_client = boto3.client("iam")

        for page in iam_client.get_paginator("list_policies").paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                try:
                    version = iam_client.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )
                    document = version["PolicyVersion"]["Document"]
                    statements = document.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                except Exception:
                    statements = []

                resources.append({
                    "resource_type": "iam_policy",
                    "provider": "aws",
                    "resource_id": policy["Arn"],
                    "is_public": False,
                    "encrypted": True,
                    "permissions": statements,
                    "tags": {},
                })

        for page in iam_client.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]
                try:
                    iam_client.get_login_profile(UserName=user_name)
                    has_console_access = True
                except Exception:
                    has_console_access = False
                try:
                    mfa = iam_client.list_mfa_devices(UserName=user_name)
                    mfa_enabled = bool(mfa.get("MFADevices"))
                except Exception:
                    mfa_enabled = False

                resources.append({
                    "resource_type": "iam_user",
                    "provider": "aws",
                    "resource_id": user_name,
                    "is_public": False,
                    "encrypted": True,
                    "permissions": [],
                    "tags": {},
                    "has_console_access": has_console_access,
                    "mfa_enabled": mfa_enabled,
                })
    except Exception:
        # Gracefully handle missing credentials or API errors
        pass

    return resources


def get_all_resources() -> list:
    """Merges every resource collector's output."""
    return get_normalized_s3_resources() + get_normalized_iam_resources()


def _get_rule_modules():
    """
    Dynamically loads all rule modules present in the rules/ directory.
    """
    rule_modules = []
    rules_dir = os.path.join(os.path.dirname(__file__), "rules")

    if os.path.exists(rules_dir):
        for filename in sorted(os.listdir(rules_dir)):
            if filename.endswith(".py") and not filename.startswith("__"):
                mod_name = filename[:-3]
                mod = None

                # Attempt package imports first, fallback to spec loading
                for import_path in [
                    f"lambdas.rule_engine.rules.{mod_name}",
                    f"rules.{mod_name}",
                ]:
                    try:
                        mod = importlib.import_module(import_path)
                        break
                    except ModuleNotFoundError:
                        continue

                if mod is None:
                    file_path = os.path.join(rules_dir, filename)
                    spec = importlib.util.spec_from_file_location(mod_name, file_path)
                    if spec and spec.loader:
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)

                if mod and hasattr(mod, "check") and callable(mod.check):
                    rule_modules.append(mod)

    return rule_modules


def run_rule_engine(resources: list) -> list:
    """
    Runs all rule modules against the provided list of normalized resources.
    Returns a list of violation dictionaries.
    """
    rule_modules = _get_rule_modules()
    violations = []

    for resource in resources:
        for rule_mod in rule_modules:
            result = rule_mod.check(resource)
            if isinstance(result, dict) and not result.get("compliant", True):
                rule_name = result.get("rule", "unknown")
                resource_id = result.get("resource_id", resource.get("resource_id"))
                clause = RULE_TO_CLAUSE.get(rule_name, "N/A")
                violations.append({
                    "rule": rule_name,
                    "resource_id": resource_id,
                    "clause": clause,
                    "compliant": False,
                })

    return violations


def report_to_aws_config(event: dict, violations: list) -> None:
    from datetime import datetime, timezone

    rules_hit = sorted({v["rule"] for v in violations})
    annotation = ("Violations: " + ", ".join(rules_hit)) if rules_hit else "No violations"
    boto3.client("config").put_evaluations(
        Evaluations=[{
            "ComplianceResourceType": "AWS::::Account",
            "ComplianceResourceId": event.get("accountId", "unknown"),
            "ComplianceType": "NON_COMPLIANT" if violations else "COMPLIANT",
            "Annotation": annotation[:256],
            "OrderingTimestamp": datetime.now(timezone.utc),
        }],
        ResultToken=event["resultToken"],
    )


def lambda_handler(event, context):
    """
    AWS Lambda handler entry point returning detected violations as JSON.
    """
    if isinstance(event, dict) and "resources" in event:
        resources = event["resources"]
    else:
        resources = get_all_resources()

    violations = run_rule_engine(resources)

    # Invoked as an AWS Config custom rule: report account-level compliance back to Config
    if isinstance(event, dict) and event.get("resultToken"):
        report_to_aws_config(event, violations)

    return {
        "statusCode": 200,
        "body": json.dumps(violations),
    }


if __name__ == "__main__":
    resources = get_all_resources()
    print(f"[DETECT] Scanned {len(resources)} resources (S3 + IAM).")
    violations = run_rule_engine(resources)
    if violations:
        for violation in violations:
            print(f"[DETECT] Violation found: {violation}")
    else:
        print("[DETECT] No rule violations found.")
