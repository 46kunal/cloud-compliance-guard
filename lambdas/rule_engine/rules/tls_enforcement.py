"""
Rule: tls_enforcement   (profile: india)
S3 buckets should deny requests that do not use TLS (bucket policy Deny with
aws:SecureTransport=false). Supports encryption-in-transit expectations (DPDP Rule 6, SPDI Rules).
Only flagged when the bucket policy was read successfully (key `tls_enforced` present).
"""
PROFILE = "india"


def check(resource: dict) -> dict:
    compliant = not (resource.get("resource_type") == "object_storage" and resource.get("tls_enforced") is False)
    return {"compliant": compliant, "rule": "tls_enforcement", "resource_id": resource.get("resource_id", "")}
