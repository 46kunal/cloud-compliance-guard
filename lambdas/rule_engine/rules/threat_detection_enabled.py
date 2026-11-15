"""
Rule: threat_detection_enabled   (profile: india)
Breach detection supports DPDP Rule 7 and CERT-In six-hour reporting: without detection an
organisation cannot know when the clock starts. Flags the account when no GuardDuty detector is
enabled. Detection alone does not meet the reporting duty.
"""
PROFILE = "india"


def check(resource: dict) -> dict:
    compliant = not (resource.get("resource_type") == "cloudtrail_config" and resource.get("guardduty_enabled") is False)
    return {"compliant": compliant, "rule": "threat_detection_enabled", "resource_id": resource.get("resource_id", "")}
