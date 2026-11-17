"""
Rule: log_location_india   (profile: india)
Flags the account when a CloudTrail trail delivers logs to an S3 bucket or CloudWatch log group outside
ap-south-1 / ap-south-2. The CERT-In direction says logs are kept within Indian jurisdiction, but its FAQ (Q35)
says logs may also be stored outside India if they can be produced to CERT-In in a reasonable time. IRDAI
(2023 guidelines), SEBI (CSCRF) and RBI (payment data) are stricter. So this is a review pointer, not a legal
finding. Other log destinations are not checked.
"""
PROFILE = "india"


def _personal(resource):
    return str((resource.get("tags") or {}).get("handles_personal_data", "")).lower() in ("true", "1", "yes")


def check(resource: dict) -> dict:
    outside = resource.get("trail_logs_outside_india")
    compliant = not (resource.get("resource_type") == "cloudtrail_config" and isinstance(outside, list) and outside)
    return {"compliant": compliant, "rule": "log_location_india", "resource_id": resource.get("resource_id", "")}
