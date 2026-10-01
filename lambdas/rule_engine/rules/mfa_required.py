"""
Rule: mfa_required
Flags IAM users that have console access (login profile) but no MFA device.
Expects resource_type "iam_user" with "has_console_access" and "mfa_enabled" keys.
"""


def check(resource: dict) -> dict:
    is_compliant = True
    if resource.get("resource_type") == "iam_user":
        needs_mfa = resource.get("has_console_access", True)
        is_compliant = not needs_mfa or bool(resource.get("mfa_enabled", False))

    return {
        "compliant": is_compliant,
        "rule": "mfa_required",
        "resource_id": resource.get("resource_id", ""),
    }
