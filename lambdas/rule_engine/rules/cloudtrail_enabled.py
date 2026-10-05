"""
Rule: cloudtrail_enabled
CIS AWS Foundations 3.1 — the account must have at least one multi-region CloudTrail trail
that is actively logging. Works on the single account-level resource
(resource_type "cloudtrail_config") produced by get_normalized_cloudtrail_resources().
"""


def check(resource: dict) -> dict:
    is_compliant = True
    if resource.get("resource_type") == "cloudtrail_config":
        is_compliant = bool(resource.get("active_multi_region_trail", False))

    return {
        "compliant": is_compliant,
        "rule": "cloudtrail_enabled",
        "resource_id": resource.get("resource_id", ""),
    }
