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
        RULE_TO_CLAUSE = {"public_storage": "GDPR Article 32 — Security of Processing"}


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

            resources.append({
                "resource_type": "object_storage",
                "provider": "aws",
                "resource_id": bucket_name,
                "is_public": is_public,
                "encrypted": False,
                "permissions": [],
                "tags": {},
            })
    except Exception as e:
        # Gracefully handle missing credentials or API errors
        pass

    return resources


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


def lambda_handler(event, context):
    """
    AWS Lambda handler entry point returning detected violations as JSON.
    """
    if isinstance(event, dict) and "resources" in event:
        resources = event["resources"]
    else:
        resources = get_normalized_s3_resources()

    violations = run_rule_engine(resources)
    return {
        "statusCode": 200,
        "body": json.dumps(violations),
    }


if __name__ == "__main__":
    resources = get_normalized_s3_resources()
    violations = run_rule_engine(resources)
    if violations:
        for violation in violations:
            print(f"[DETECT] Violation found: {violation}")
    else:
        print("[DETECT] No rule violations found.")
