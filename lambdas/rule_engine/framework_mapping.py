PRIVACY_CLAUSE_MAP = {
    "public_storage": "DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (also GDPR Art. 32)",
    "encryption_at_rest": "DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (also GDPR Art. 32)",
    "mfa_required": "DPDP Act 2023 Sec. 8(5) — Access Control Safeguard",
    "open_admin_ports": "DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (Network Exposure)",
    "iam_wildcard_policy": "DPDP Act 2023 Sec. 8(5) — Access Control Safeguard",
    "wildcard_permission": "DPDP Act 2023 Sec. 8(5) — Access Control Safeguard",
    "cloudtrail_enabled": "DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (Audit Logging)",
    "data_residency_india": "DPDP Act 2023 Sec. 16 — Transfer Outside India (review pointer)",
    "tls_enforcement": "DPDP Rules 2025 Rule 6 — Encryption of Personal Data in Transit",
    "log_retention_180d": "CERT-In Directions 2022 — 180-day Log Retention",
    "log_retention_365d": "DPDP Rules 2025 Rule 6 — One-year Log Retention",
    "s3_versioning": "DPDP Rules 2025 Rule 6 — Backup and Continuity Safeguard",
    "threat_detection_enabled": "DPDP Rules 2025 Rule 7 — Breach Detection Capability",
}

SECURITY_CONTROL_MAP = {
    "public_storage": "CIS AWS Foundations Benchmark — Restrict Public Access to Storage",
    "encryption_at_rest": "CIS AWS Foundations Benchmark — Storage Encryption at Rest",
    "mfa_required": "CIS AWS Foundations Benchmark 1.13/1.14 — Multi-Factor Authentication",
    "open_admin_ports": "CIS AWS Foundations Benchmark 4.1/4.2 — Restrict Admin Ports (SSH/RDP)",
    "iam_wildcard_policy": "CIS AWS Foundations Benchmark — IAM Least Privilege",
    "wildcard_permission": "CIS AWS Foundations Benchmark — IAM Least Privilege",
    "cloudtrail_enabled": "CIS AWS Foundations Benchmark 3.1 — CloudTrail Enabled in All Regions",
    "data_residency_india": "Indian data-localisation guidance (RBI/SEBI/IRDAI) — Indian Regions (review pointer)",
    "tls_enforcement": "CIS AWS Foundations Benchmark 2.1.1 — Deny HTTP Requests to S3",
    "log_retention_180d": "CERT-In Directions 2022 — 180-day Log Retention",
    "log_retention_365d": "DPDP Rules 2025 Rule 6 — One-year Log Retention",
    "s3_versioning": "AWS Well-Architected Security — S3 Versioning for Recovery",
    "threat_detection_enabled": "CERT-In Directions 2022 — Incident Detection and 6-hour Reporting Readiness",
}

RULE_TO_CLAUSE = SECURITY_CONTROL_MAP
