"""
Rule: vpc_flow_logs   (profile: india)
Network traffic logging supports incident investigation (CERT-In log duties, DPDP Rule 6 logging).
Flags the account when any VPC in the scanned region has no active flow log. Only VPC-level flow logs
are counted; subnet or interface level logs are not. Not flagged when VPCs could not be read.
"""
PROFILE = "india"


def _personal(resource):
    return str((resource.get("tags") or {}).get("handles_personal_data", "")).lower() in ("true", "1", "yes")


def check(resource: dict) -> dict:
    missing = resource.get("vpcs_without_flow_logs")
    compliant = not (resource.get("resource_type") == "cloudtrail_config" and isinstance(missing, list) and missing)
    return {"compliant": compliant, "rule": "vpc_flow_logs", "resource_id": resource.get("resource_id", "")}
