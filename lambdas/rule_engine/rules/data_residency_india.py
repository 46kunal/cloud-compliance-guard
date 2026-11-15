"""
Rule: data_residency_india   (profile: india)
Data stores and network resources should live in Indian AWS regions (ap-south-1 Mumbai,
ap-south-2 Hyderabad). This is a review pointer toward data-localisation duties in sector rules
(RBI, SEBI, IRDAI) and DPDP s.16, not a legal finding: whether a transfer is lawful depends on
the data and the entity. Resources whose region was not collected are not flagged.
"""
PROFILE = "india"
INDIA_REGIONS = ("ap-south-1", "ap-south-2")
CHECKED_TYPES = ("object_storage", "security_group", "block_storage", "database")


def check(resource: dict) -> dict:
    region = resource.get("region")
    compliant = (resource.get("resource_type") not in CHECKED_TYPES) or not region or region in INDIA_REGIONS
    return {"compliant": compliant, "rule": "data_residency_india", "resource_id": resource.get("resource_id", "")}
