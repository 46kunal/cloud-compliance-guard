"""
Rule: stale_access_keys   (profile: india)
Active IAM access keys should be rotated (CIS 1.14 suggests 90 days; DPDP Rule 6 access control).
The age limit comes from POLICYGUARD_KEY_MAX_AGE_DAYS (default 90) and is a policy choice, not a legal
number. Flags users who have an active key at or past the limit. Not flagged when keys could not be read.
"""
PROFILE = "india"


def _personal(resource):
    return str((resource.get("tags") or {}).get("handles_personal_data", "")).lower() in ("true", "1", "yes")


def check(resource: dict) -> dict:
    stale = resource.get("stale_access_keys")
    compliant = not (resource.get("resource_type") == "iam_user" and isinstance(stale, list) and stale)
    return {"compliant": compliant, "rule": "stale_access_keys", "resource_id": resource.get("resource_id", "")}
