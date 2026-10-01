"""
Action: enforce_encryption
Sets default SSE-S3 (AES256) server-side encryption on the bucket.
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

ACTION = "enforce_encryption"


def remediate(resource_id: str, dry_run: bool = True) -> dict:
    result = {"action": ACTION, "resource_id": resource_id, "dry_run": dry_run, "success": False}

    if dry_run:
        result.update(success=True, message=f"Would enable AES256 default encryption on s3://{resource_id}")
        return result
    if not is_remediation_allowed(resource_id):
        result["message"] = "Skipped: resource not in allowlist"
        return result

    try:
        boto3.client("s3").put_bucket_encryption(
            Bucket=resource_id,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        result.update(success=True, message=f"AES256 default encryption enabled on s3://{resource_id}")
    except Exception as e:
        result["message"] = f"Error: {e}"
    return result
