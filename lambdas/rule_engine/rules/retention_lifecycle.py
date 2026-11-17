"""
Rule: retention_lifecycle   (profile: india)
A lifecycle (expiry) rule is the technical hook for erasing personal data when its purpose ends
(DPDP s.8(7)). Only buckets tagged handles_personal_data=true are flagged. This shows a policy exists,
not that deletion actually happens when it should; that stays a process question.
"""
PROFILE = "india"


def _personal(resource):
    return str((resource.get("tags") or {}).get("handles_personal_data", "")).lower() in ("true", "1", "yes")


def check(resource: dict) -> dict:
    compliant = not (resource.get("resource_type") == "object_storage" and _personal(resource)
                     and resource.get("lifecycle_defined") is False)
    return {"compliant": compliant, "rule": "retention_lifecycle", "resource_id": resource.get("resource_id", "")}
