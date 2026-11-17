"""
Rule: root_mfa   (profile: india)
The AWS root account must have MFA enabled and no access keys (CIS 1.5 and 1.4; DPDP Rule 6 access control).
Evaluated on the account summary only. Not flagged when the summary could not be read.
"""
PROFILE = "india"


def _personal(resource):
    return str((resource.get("tags") or {}).get("handles_personal_data", "")).lower() in ("true", "1", "yes")


def check(resource: dict) -> dict:
    compliant = True
    if resource.get("resource_type") == "iam_account" and "root_mfa_enabled" in resource:
        compliant = bool(resource.get("root_mfa_enabled")) and not resource.get("root_access_keys_present", False)
    return {"compliant": compliant, "rule": "root_mfa", "resource_id": resource.get("resource_id", "")}
