"""
Rule: open_admin_ports
Checks if an EC2 Security Group allows unrestricted inbound access (0.0.0.0/0 or ::/0)
to administrative ports such as 22 (SSH) or 3389 (RDP).
"""

ADMIN_PORTS = {22, 3389}


def _has_open_admin_port(permissions: list) -> bool:
    for rule in permissions:
        if not isinstance(rule, dict):
            continue
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        ip_protocol = rule.get("IpProtocol", "")

        applies_to_admin_port = False
        if ip_protocol == "-1":
            applies_to_admin_port = True
        elif from_port is not None and to_port is not None:
            for port in ADMIN_PORTS:
                if from_port <= port <= to_port:
                    applies_to_admin_port = True
                    break

        if not applies_to_admin_port:
            continue

        ip_ranges = [r.get("CidrIp") for r in rule.get("IpRanges", []) if isinstance(r, dict)]
        ipv6_ranges = [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", []) if isinstance(r, dict)]

        if "0.0.0.0/0" in ip_ranges or "::/0" in ipv6_ranges:
            return True

    return False


def check(resource: dict) -> dict:
    """
    Evaluates a normalized resource dictionary.
    Returns compliance result dictionary.
    """
    resource_id = resource.get("resource_id", "")
    resource_type = resource.get("resource_type", "")
    permissions = resource.get("permissions", [])

    if resource_type != "security_group":
        return {"compliant": True, "rule": "open_admin_ports", "resource_id": resource_id}

    has_open_port = _has_open_admin_port(permissions)
    is_compliant = not has_open_port

    return {
        "compliant": is_compliant,
        "rule": "open_admin_ports",
        "resource_id": resource_id,
    }
