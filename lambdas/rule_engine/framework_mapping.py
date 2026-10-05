PRIVACY_CLAUSE_MAP = {
    "public_storage": "DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (also GDPR Art. 32)",
    "encryption_at_rest": "DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (also GDPR Art. 32)",
    "mfa_required": "DPDP Act 2023 Sec. 8(5) — Access Control Safeguard",
    "open_admin_ports": "DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (Network Exposure)",
    "iam_wildcard_policy": "DPDP Act 2023 Sec. 8(5) — Access Control Safeguard",
    "wildcard_permission": "DPDP Act 2023 Sec. 8(5) — Access Control Safeguard",
    "cloudtrail_enabled": "DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (Audit Logging)",
}

SECURITY_CONTROL_MAP = {
    "public_storage": "CIS AWS Foundations Benchmark — Restrict Public Access to Storage",
    "encryption_at_rest": "CIS AWS Foundations Benchmark — Storage Encryption at Rest",
    "mfa_required": "CIS AWS Foundations Benchmark 1.13/1.14 — Multi-Factor Authentication",
    "open_admin_ports": "CIS AWS Foundations Benchmark 4.1/4.2 — Restrict Admin Ports (SSH/RDP)",
    "iam_wildcard_policy": "CIS AWS Foundations Benchmark — IAM Least Privilege",
    "wildcard_permission": "CIS AWS Foundations Benchmark — IAM Least Privilege",
    "cloudtrail_enabled": "CIS AWS Foundations Benchmark 3.1 — CloudTrail Enabled in All Regions",
}

RULE_TO_CLAUSE = SECURITY_CONTROL_MAP
