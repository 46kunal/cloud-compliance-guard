"""
Action: close_public_bucket
Enables all four S3 Public Access Block settings on the bucket.
"""
import boto3

try:
    from lambdas.remediation.safety.dry_run import is_remediation_allowed
except ModuleNotFoundError:
    try:
        from safety.dry_run import is_remediation_allowed
    except ModuleNotFoundError:
        import importlib.util
        import os
        _path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "safety", "dry_run.py")
        _spec = importlib.util.spec_from_file_location("dry_run", _path)
        _mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        is_remediation_allowed = _mod.is_remediation_allowed

ACTION = "close_public_bucket"


def remediate(resource_id: str, dry_run: bool = True) -> dict:
    result = {"action": ACTION, "resource_id": resource_id, "dry_run": dry_run, "success": False}

    if dry_run:
        result.update(success=True, message=f"Would enable Public Access Block on s3://{resource_id}")
        return result
    if not is_remediation_allowed(resource_id):
        result["message"] = "Skipped: resource not in allowlist"
        return result

    try:
        boto3.client("s3").put_public_access_block(
            Bucket=resource_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        result.update(success=True, message=f"Public Access Block enabled on s3://{resource_id}")
    except Exception as e:
        result["message"] = f"Error: {e}"
    return result
