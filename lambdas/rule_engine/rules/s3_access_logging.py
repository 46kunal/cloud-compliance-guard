"""
Rule: s3_access_logging   (profile: india)
Server access logging records who touched personal data (DPDP Rule 6 logging and monitoring).
Only buckets tagged handles_personal_data=true are flagged, to avoid noise on log buckets themselves.
Not flagged when the logging state could not be read.
"""
PROFILE = "india"


def _personal(resource):
    return str((resource.get("tags") or {}).get("handles_personal_data", "")).lower() in ("true", "1", "yes")


def check(resource: dict) -> dict:
    compliant = not (resource.get("resource_type") == "object_storage" and _personal(resource)
                     and resource.get("logging_enabled") is False)
    return {"compliant": compliant, "rule": "s3_access_logging", "resource_id": resource.get("resource_id", "")}
