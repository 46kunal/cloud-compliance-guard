"""
Severity rules module for risk classification.
"""

def classify(violation: dict) -> str:
    """
    Returns severity level ("HIGH", "MEDIUM", "LOW") based on violation rule.
    - HIGH: public_storage, wildcard_permission, open_admin_ports
    - MEDIUM: encryption_at_rest, mfa_required
    - LOW: otherwise
    """
    rule = violation.get("rule", "") if isinstance(violation, dict) else ""

    if rule in ("public_storage", "wildcard_permission", "open_admin_ports"):
        return "HIGH"
    elif rule in ("encryption_at_rest", "mfa_required"):
        return "MEDIUM"
    else:
        return "LOW"
