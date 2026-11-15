"""
Rule: log_retention_180d   (profile: india)
CERT-In Directions (28 April 2022): ICT system logs must be kept for a rolling 180 days.
Flags the account when any CloudWatch log group expires events sooner than 180 days. Log groups
with no expiry pass. Applies to every log group in the account; review which ones are in scope.
"""
PROFILE = "india"
MIN_DAYS = 180


def check(resource: dict) -> dict:
    groups = resource.get("short_retention_log_groups")
    compliant = True
    if resource.get("resource_type") == "cloudtrail_config" and isinstance(groups, list):
        compliant = not any(isinstance(g.get("days"), (int, float)) and g["days"] < MIN_DAYS for g in groups)
    return {"compliant": compliant, "rule": "log_retention_180d", "resource_id": resource.get("resource_id", "")}
