"""
Rule: encryption_at_rest
Checks that storage resources (S3 buckets, EBS volumes) are encrypted at rest.
"""

STORAGE_TYPES = ("object_storage", "block_storage")


def check(resource: dict) -> dict:
    resource_type = resource.get("resource_type", "")
    encrypted = resource.get("encrypted", False)

    is_compliant = resource_type not in STORAGE_TYPES or bool(encrypted)

    return {
        "compliant": is_compliant,
        "rule": "encryption_at_rest",
        "resource_id": resource.get("resource_id", ""),
    }
