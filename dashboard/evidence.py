"""Build safe, scan-specific evidence from normalized collector records."""
import hashlib
import json


RULE_DETAILS = {
    "public_storage": (
        "is_public", False,
        "The collector observed that the storage resource is publicly accessible.",
    ),
    "encryption_at_rest": (
        "encrypted", True,
        "The collector observed that the storage resource does not use the encryption condition required by this rule.",
    ),
    "wildcard_permission": (
        "permissions", "least privilege",
        "The collected IAM policy contains an Allow statement with wildcard action and resource access.",
    ),
    "mfa_required": (
        "console_access_and_mfa", "MFA enabled for console access",
        "The collected IAM user has console access and no MFA device was reported.",
    ),
    "open_admin_ports": (
        "ingress_rules", "administrative ports not open to the internet",
        "The collected security group permits unrestricted inbound access to SSH or RDP.",
    ),
    "cloudtrail_enabled": (
        "active_multi_region_trail", True,
        "The collector did not observe an active multi-region CloudTrail trail.",
    ),
}

SERVICE_BY_TYPE = {
    "object_storage": "s3", "iam_policy": "iam", "iam_user": "iam",
    "security_group": "ec2", "cloudtrail_config": "cloudtrail",
}
RULE_GUIDANCE = {
    "public_storage": "Restrict public access to the storage resource using the existing public-storage remediation guidance.",
    "encryption_at_rest": "Enable encryption at rest using the existing encryption remediation guidance.",
    "wildcard_permission": "Remove wildcard permissions and grant only required IAM actions and resources.",
    "mfa_required": "Enable an MFA device for the IAM user's console access.",
    "open_admin_ports": "Restrict SSH/RDP ingress to approved source ranges.",
    "cloudtrail_enabled": "Enable an actively logging multi-region CloudTrail trail.",
}

SENSITIVE_KEY_PARTS = ("secret", "password", "credential", "accesskey", "token", "privatekey")


def _safe_value(value, key=""):
    """Copy JSON-compatible evidence while excluding fields likely to contain credentials."""
    if any(part in str(key).replace("_", "").lower() for part in SENSITIVE_KEY_PARTS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _safe_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _observed(rule, resource):
    if rule in ("public_storage", "encryption_at_rest", "cloudtrail_enabled"):
        key = RULE_DETAILS[rule][0]
        return {key: resource.get(key)}
    if rule == "mfa_required":
        return {"has_console_access": resource.get("has_console_access"),
                "mfa_enabled": resource.get("mfa_enabled")}
    if rule == "wildcard_permission":
        matching = []
        statements = resource.get("permissions", [])
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements if isinstance(statements, list) else []:
            if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                continue
            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])
            actions = actions if isinstance(actions, list) else [actions]
            resources = resources if isinstance(resources, list) else [resources]
            if any(a == "*" or str(a).endswith(":*") for a in actions) and "*" in resources:
                matching.append(statement)
        return {"matching_policy_statements": matching}
    if rule == "open_admin_ports":
        permissions = resource.get("permissions", [])
        matching = []
        for permission in permissions if isinstance(permissions, list) else []:
            if not isinstance(permission, dict):
                continue
            protocol = permission.get("IpProtocol", "")
            start, end = permission.get("FromPort"), permission.get("ToPort")
            port_matches = protocol == "-1" or (
                start is not None and end is not None and
                any(start <= port <= end for port in (22, 3389))
            )
            public = any(isinstance(item, dict) and item.get("CidrIp") == "0.0.0.0/0"
                         for item in permission.get("IpRanges", [])) or any(
                isinstance(item, dict) and item.get("CidrIpv6") == "::/0"
                for item in permission.get("Ipv6Ranges", []))
            if port_matches and public:
                matching.append(permission)
        return {"matching_ingress_rules": matching}
    return {}


def build_evidence_records(classified, resources, scan_id, detected_at, account_scope, region_scope,
                           collection_report=None):
    """Build one evidence snapshot per evaluated finding from the same scan's inputs."""
    resources_by_id = {(resource.get("resource_type"), resource.get("resource_id")): resource for resource in resources
                       if isinstance(resource, dict)}
    records = []
    for finding in classified:
        resource = resources_by_id.get((finding.get("resource_type"), finding.get("resource_id")))
        rule = finding.get("rule")
        if not resource or rule not in RULE_DETAILS:
            continue
        service = SERVICE_BY_TYPE.get(resource.get("resource_type"))
        service_result = (collection_report or {}).get(service, {})
        if service_result.get("status") in ("FAILED", "NOT_SCANNED") or resource.get("_collection_complete") is False:
            continue
        _observed_key, expected, explanation = RULE_DETAILS[rule]
        observed = _safe_value(_observed(rule, resource))
        remediation_guidance = finding.get("remediation")
        if not remediation_guidance:
            remediation_guidance = RULE_GUIDANCE[rule]
        required_keys = {
            "public_storage": ("is_public",), "encryption_at_rest": ("encrypted",),
            "wildcard_permission": ("permissions",), "mfa_required": ("has_console_access", "mfa_enabled"),
            "open_admin_ports": ("permissions",), "cloudtrail_enabled": ("active_multi_region_trail",),
        }[rule]
        collection_status = "COLLECTED" if all(key in resource for key in required_keys) else "PARTIAL"
        if collection_status == "PARTIAL":
            explanation = "The rule evaluated the available collector data, but one or more required configuration fields were missing. Review the observed values and collection status before drawing conclusions."
        evidence = {
            "finding_id": None,
            "rule": rule,
            "lifecycle_status": None,
            "severity": finding.get("severity"),
            "provider": finding.get("provider", "aws"),
            "resource_id": finding.get("resource_id"),
            "resource_type": resource.get("resource_type"),
            "service": service,
            "account_scope": finding.get("account_scope", account_scope),
            "region_scope": region_scope,
            "observed_configuration": observed,
            "expected_condition": expected,
            "explanation": explanation,
            "compliance_mapping": finding.get("clause") if finding.get("clause") not in (None, "", "N/A") else "Not mapped",
            "detected_at": detected_at,
            "scan_id": scan_id,
            "evidence_source": service,
            "rule_reference": rule,
            "collection_status": collection_status,
            "scan_status": None,
            "recommended_action": _safe_value(remediation_guidance),
        }
        records.append({"rule": rule, "resource_id": finding.get("resource_id"), "evidence": evidence})
    return records


def canonical_evidence(evidence):
    """Return deterministic JSON and SHA-256 for integrity checking, not authenticity."""
    serialized = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return serialized, hashlib.sha256(serialized.encode("utf-8")).hexdigest()
