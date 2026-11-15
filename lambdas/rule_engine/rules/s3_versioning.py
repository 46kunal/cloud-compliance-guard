"""
Rule: s3_versioning   (profile: india)
Versioning gives point-in-time recovery for stored objects (backup / continuity safeguard,
DPDP Rule 6 as summarised, SPDI Rules). Flagged only when the versioning state was collected.
"""
PROFILE = "india"


def check(resource: dict) -> dict:
    compliant = not (resource.get("resource_type") == "object_storage" and resource.get("versioning_enabled") is False)
    return {"compliant": compliant, "rule": "s3_versioning", "resource_id": resource.get("resource_id", "")}
