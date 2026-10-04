"""
Tier Classifier Module for PolicyGuard.

Classifies AWS resources into 'PRIVACY' or 'SECURITY' compliance tiers
based on resource tags (specifically 'handles_personal_data' and 'data-type').
"""


def classify_tier(resource: dict) -> str:
    """
    Classifies a resource into 'PRIVACY' or 'SECURITY' tier.

    Inspects resource['tags']:
    - Returns 'PRIVACY' if handles_personal_data is true/1/yes or data-type represents personal data.
    - Returns 'SECURITY' otherwise.
    """
    if not isinstance(resource, dict):
        return "SECURITY"

    tags = resource.get("tags", {})
    normalized_tags = {}

    if isinstance(tags, dict):
        for k, v in tags.items():
            normalized_tags[str(k).lower()] = str(v).lower()
    elif isinstance(tags, list):
        for tag_dict in tags:
            if isinstance(tag_dict, dict) and "Key" in tag_dict and "Value" in tag_dict:
                normalized_tags[str(tag_dict["Key"]).lower()] = str(tag_dict["Value"]).lower()

    # Check explicit handles_personal_data tag
    hpd = normalized_tags.get("handles_personal_data")
    if hpd in ("true", "1", "yes"):
        return "PRIVACY"
    elif hpd in ("false", "0", "no"):
        return "SECURITY"

    # Check secondary data-type tag
    dt = normalized_tags.get("data-type")
    if dt in ("user-records", "pii", "personal", "customer-data"):
        return "PRIVACY"

    return "SECURITY"
