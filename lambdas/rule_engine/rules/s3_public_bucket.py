"""
Rule: s3_public_bucket
Checks if an S3 bucket (object storage) is configured as public.
"""

def check(resource: dict) -> dict:
    """
    Evaluates a normalized resource dictionary.
    Returns compliance result dictionary.
    """
    resource_id = resource.get("resource_id", "")
    resource_type = resource.get("resource_type", "")
    is_public = resource.get("is_public", False)

    # Flag non-compliant when is_public is True and resource_type is "object_storage"
    is_compliant = not (is_public and resource_type == "object_storage")

    return {
        "compliant": is_compliant,
        "rule": "public_storage",
        "resource_id": resource_id,
    }
