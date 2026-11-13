import importlib
import importlib.util
import json
import os
import sys
import boto3

try:
    from lambdas.rule_engine.framework_mapping import (
        PRIVACY_CLAUSE_MAP,
        SECURITY_CONTROL_MAP,
        RULE_TO_CLAUSE,
    )
except ModuleNotFoundError:
    try:
        from framework_mapping import (
            PRIVACY_CLAUSE_MAP,
            SECURITY_CONTROL_MAP,
            RULE_TO_CLAUSE,
        )
    except ModuleNotFoundError:
        _fm_path = os.path.join(os.path.dirname(__file__), "framework_mapping.py")
        _spec = importlib.util.spec_from_file_location("framework_mapping", _fm_path)
        _fm = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_fm)
        PRIVACY_CLAUSE_MAP = _fm.PRIVACY_CLAUSE_MAP
        SECURITY_CONTROL_MAP = _fm.SECURITY_CONTROL_MAP
        RULE_TO_CLAUSE = _fm.RULE_TO_CLAUSE

try:
    from lambdas.tier_classifier import classify_tier
except ModuleNotFoundError:
    try:
        from tier_classifier import classify_tier
    except ModuleNotFoundError:
        def classify_tier(res):
            tags = res.get("tags", {}) if isinstance(res, dict) else {}
            hpd = str(tags.get("handles_personal_data", "")).lower()
            return "PRIVACY" if hpd in ("true", "1", "yes") else "SECURITY"


def _policy_allows_anyone(policy: dict) -> bool:
    """True if any unconditional Allow statement has Principal "*" (or {"AWS": "*"})."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for s in statements:
        principal = s.get("Principal")
        anyone = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"]))
        if s.get("Effect") == "Allow" and anyone and not s.get("Condition"):
            return True
    return False


def _record_collection(report, service, status="SUCCESS", error=None):
    """Accumulate collector health without changing the collector's resource return contract."""
    if report is None:
        return
    current = report.setdefault(service, {"status": "SUCCESS", "errors": []})
    rank = {"SUCCESS": 0, "PARTIAL": 1, "FAILED": 2}
    if current.get("status") == "NOT_SCANNED":
        current["status"] = "SUCCESS"
    if rank.get(status, 2) > rank.get(current["status"], 0):
        current["status"] = status
    if error:
        current["errors"].append(str(error))


def _permission_or_api_failure(error, expected_absence=()):
    response = getattr(error, "response", {}) or {}
    code = response.get("Error", {}).get("Code", "")
    return code not in set(expected_absence)


def get_normalized_s3_resources(collection_report=None) -> list:
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

            resource_complete = True
            is_public = False
            try:
                policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
                is_public = policy_status.get("PolicyStatus", {}).get("IsPublic", False)
                if not is_public:
                    # Emulators (moto/LocalStack) don't compute IsPublic: evaluate the policy ourselves too
                    policy = json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"])
                    is_public = _policy_allows_anyone(policy)
            except Exception as e:
                if _permission_or_api_failure(e, ("NoSuchBucketPolicy",)):
                    _record_collection(collection_report, "s3", "PARTIAL", f"Bucket policy status/policy could not be read: {e}")
                    resource_complete = False
                is_public = False

            # Public Access Block fully enabled overrides a public policy
            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)
                cfg = pab.get("PublicAccessBlockConfiguration", {})
                if cfg.get("BlockPublicPolicy") and cfg.get("RestrictPublicBuckets"):
                    is_public = False
            except Exception as e:
                if _permission_or_api_failure(e, ("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock")):
                    _record_collection(collection_report, "s3", "PARTIAL", f"Bucket public access block could not be read: {e}")
                    resource_complete = False
                pass

            encrypted = False
            try:
                enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                for r in rules:
                    algo = r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                    if algo in ("aws:kms", "aws:kms:dsse"):
                        encrypted = True
                        break
            except Exception as e:
                if _permission_or_api_failure(e, ("ServerSideEncryptionConfigurationNotFoundError",)):
                    _record_collection(collection_report, "s3", "PARTIAL", f"Bucket encryption could not be read: {e}")
                    resource_complete = False
                encrypted = False

            tags = {}
            try:
                tag_res = s3_client.get_bucket_tagging(Bucket=bucket_name)
                tags = {t["Key"]: t["Value"] for t in tag_res.get("TagSet", []) if "Key" in t and "Value" in t}
            except Exception as e:
                if _permission_or_api_failure(e, ("NoSuchTagSet",)):
                    _record_collection(collection_report, "s3", "PARTIAL", f"Bucket tags could not be read: {e}")
                    resource_complete = False
                tags = {}

            resources.append({
                "resource_type": "object_storage",
                "provider": "aws",
                "resource_id": bucket_name,
                "is_public": is_public,
                "encrypted": encrypted,
                "permissions": [],
                "tags": tags,
                "_collection_complete": resource_complete,
            })
    except Exception as e:
        _record_collection(collection_report, "s3", "FAILED", e)
        print(f"[DETECT] WARNING: S3 scan failed: {e}", file=sys.stderr)

    _record_collection(collection_report, "s3")

    return resources


def get_normalized_iam_resources(collection_report=None) -> list:
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
                resource_complete = True
                try:
                    version = iam_client.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )
                    document = version["PolicyVersion"]["Document"]
                    statements = document.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                except Exception as e:
                    if _permission_or_api_failure(e):
                        _record_collection(collection_report, "iam", "PARTIAL", f"Policy version unavailable: {e}")
                        resource_complete = False
                    statements = []

                resources.append({
                    "resource_type": "iam_policy",
                    "provider": "aws",
                    "resource_id": policy["Arn"],
                    "is_public": False,
                    "encrypted": True,
                    "permissions": statements,
                    "tags": {},
                    "_collection_complete": resource_complete,
                })

        for page in iam_client.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]
                resource_complete = True
                try:
                    iam_client.get_login_profile(UserName=user_name)
                    has_console_access = True
                except Exception as e:
                    if _permission_or_api_failure(e, ("NoSuchEntity",)):
                        _record_collection(collection_report, "iam", "PARTIAL", f"Login profile unavailable: {e}")
                        resource_complete = False
                    has_console_access = False
                try:
                    mfa = iam_client.list_mfa_devices(UserName=user_name)
                    mfa_enabled = bool(mfa.get("MFADevices"))
                except Exception as e:
                    if _permission_or_api_failure(e):
                        _record_collection(collection_report, "iam", "PARTIAL", f"MFA devices unavailable: {e}")
                        resource_complete = False
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
                    "_collection_complete": resource_complete,
                })
    except Exception as e:
        _record_collection(collection_report, "iam", "FAILED", e)
        print(f"[DETECT] WARNING: IAM scan failed: {e}", file=sys.stderr)

    _record_collection(collection_report, "iam")

    return resources


def get_normalized_ec2_resources(collection_report=None) -> list:
    """
    Lists EC2 security groups using boto3 and returns a list of normalized resource dicts.
    """
    resources = []
    try:
        region = boto3.session.Session().region_name or "us-east-1"
        ec2_client = boto3.client("ec2", region_name=region)
        response = ec2_client.describe_security_groups()
        sgs = response.get("SecurityGroups", [])

        for sg in sgs:
            sg_id = sg.get("GroupId")
            if not sg_id:
                continue

            tags = {}
            for tag in sg.get("Tags", []):
                if "Key" in tag and "Value" in tag:
                    tags[tag["Key"]] = tag["Value"]

            ip_permissions = sg.get("IpPermissions", [])

            resources.append({
                "resource_type": "security_group",
                "provider": "aws",
                "resource_id": sg_id,
                "group_name": sg.get("GroupName"),
                "is_public": False,
                "encrypted": True,
                "permissions": ip_permissions,
                "tags": tags,
            })
    except Exception as e:
        _record_collection(collection_report, "ec2", "FAILED", e)
        print(f"[DETECT] WARNING: EC2 scan failed: {e}", file=sys.stderr)

    _record_collection(collection_report, "ec2")

    return resources


def get_normalized_cloudtrail_resources(collection_report=None) -> list:
    """
    Returns ONE account-level resource (resource_type "cloudtrail_config") saying whether an
    active multi-region CloudTrail trail exists (CIS 3.1). Returns [] on API errors, so missing
    permissions are reported as a scan warning and never as a false "no CloudTrail" finding.
    """
    try:
        region = boto3.session.Session().region_name or "us-east-1"
        trails = boto3.client("cloudtrail", region_name=region).describe_trails().get("trailList", [])

        active = False
        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                continue
            # A trail's status must be read from its home region
            home = boto3.client("cloudtrail", region_name=trail.get("HomeRegion", region))
            if home.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
                active = True
                break

        _record_collection(collection_report, "cloudtrail")
        return [{
            "resource_type": "cloudtrail_config",
            "provider": "aws",
            "resource_id": "cloudtrail:account-wide",
            "is_public": False,
            "encrypted": True,
            "permissions": [],
            "tags": {},
            "trail_count": len(trails),
            "active_multi_region_trail": active,
        }]
    except Exception as e:
        _record_collection(collection_report, "cloudtrail", "FAILED", e)
        print(f"[DETECT] WARNING: CloudTrail scan failed: {e}", file=sys.stderr)
        return []


def get_all_resources(collection_report=None) -> list:
    """Merges every resource collector's output."""
    return (
        get_normalized_s3_resources(collection_report)
        + get_normalized_iam_resources(collection_report)
        + get_normalized_ec2_resources(collection_report)
        + get_normalized_cloudtrail_resources(collection_report)
    )


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
        if resource.get("_collection_complete") is False:
            continue
        tier = classify_tier(resource)
        for rule_mod in rule_modules:
            result = rule_mod.check(resource)
            if isinstance(result, dict) and not result.get("compliant", True):
                rule_name = result.get("rule", "unknown")
                resource_id = result.get("resource_id", resource.get("resource_id"))

                if tier == "PRIVACY":
                    clause = PRIVACY_CLAUSE_MAP.get(rule_name, RULE_TO_CLAUSE.get(rule_name, "N/A"))
                else:
                    clause = SECURITY_CONTROL_MAP.get(rule_name, RULE_TO_CLAUSE.get(rule_name, "N/A"))

                violations.append({
                    "rule": rule_name,
                    "resource_id": resource_id,
                    "provider": resource.get("provider", "aws"),
                    "resource_type": resource.get("resource_type", "unknown"),
                    "clause": clause,
                    "tier": tier,
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
