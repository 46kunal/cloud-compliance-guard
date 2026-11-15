"""
Rule: log_retention_365d   (profile: india)
DPDP Rules 2025, Rule 6 (as summarised by secondary sources): logs and related personal data kept
for one year. Flags the account when any CloudWatch log group expires events sooner than 365 days.
Not yet in force (DPDP commencement is expected around May 2027).
"""
PROFILE = "india"
MIN_DAYS = 365


def check(resource: dict) -> dict:
    groups = resource.get("short_retention_log_groups")
    compliant = True
    if resource.get("resource_type") == "cloudtrail_config" and isinstance(groups, list):
        compliant = not any(isinstance(g.get("days"), (int, float)) and g["days"] < MIN_DAYS for g in groups)
    return {"compliant": compliant, "rule": "log_retention_365d", "resource_id": resource.get("resource_id", "")}
