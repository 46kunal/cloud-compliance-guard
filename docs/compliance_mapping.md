# Rule → regulation mapping

Source of truth: [`lambdas/rule_engine/framework_mapping.py`](../lambdas/rule_engine/framework_mapping.py) (`PRIVACY_CLAUSE_MAP` & `SECURITY_CONTROL_MAP`).

PolicyGuard employs a two-tier compliance architecture:
- **Tier 1 — Privacy**: Applied when a resource is tagged with `handles_personal_data=true` or `data-type=user-records`.
- **Tier 2 — Security Hygiene**: Applied to general infrastructure and technical security findings.

Each individual finding receives exactly one citation, from exactly one tier, determined at scan time by the resource's handles_personal_data tag — the tables below show both possible citations for each rule, not that both apply simultaneously.

---

### Tier 1 — Privacy (DPDP Act 2023)

| Rule | Detects | Severity | Clause | Auto-remediation |
|---|---|---|---|---|
| `public_storage` | S3 bucket public via bucket policy | HIGH | `DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (also GDPR Art. 32)` | `close_public_bucket` |
| `encryption_at_rest` | S3 bucket without SSE-KMS default encryption | MEDIUM | `DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (also GDPR Art. 32)` | `enforce_encryption` (SSE-KMS) |
| `mfa_required` | IAM user with console access and no MFA device | MEDIUM | `DPDP Act 2023 Sec. 8(5) — Access Control Safeguard` | Manual review |
| `open_admin_ports` | Security Group allowing 0.0.0.0/0 on port 22/3389 | HIGH | `DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (Network Exposure)` | Manual review |
| `wildcard_permission` | IAM policy with `Allow` of `*` (or `service:*`) on `Resource: *` | HIGH | `DPDP Act 2023 Sec. 8(5) — Access Control Safeguard` | `revoke_iam_permission` |
| `cloudtrail_enabled` | No active multi-region CloudTrail trail | MEDIUM | `DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (Audit Logging)` | Manual review |

---

### Tier 2 — Security Hygiene (CIS AWS Foundations Benchmark)

| Rule | Detects | Severity | Clause | Auto-remediation |
|---|---|---|---|---|
| `public_storage` | S3 bucket public via bucket policy | HIGH | `CIS AWS Foundations Benchmark — Restrict Public Access to Storage` | `close_public_bucket` |
| `encryption_at_rest` | S3 bucket without SSE-KMS default encryption | MEDIUM | `CIS AWS Foundations Benchmark — Storage Encryption at Rest` | `enforce_encryption` (SSE-KMS) |
| `mfa_required` | IAM user with console access and no MFA device | MEDIUM | `CIS AWS Foundations Benchmark 1.13/1.14 — Multi-Factor Authentication` | Manual review |
| `open_admin_ports` | Security Group allowing 0.0.0.0/0 on port 22/3389 | HIGH | `CIS AWS Foundations Benchmark 4.1/4.2 — Restrict Admin Ports (SSH/RDP)` | Manual review |
| `wildcard_permission` | IAM policy with `Allow` of `*` (or `service:*`) on `Resource: *` | HIGH | `CIS AWS Foundations Benchmark — IAM Least Privilege` | `revoke_iam_permission` |
| `cloudtrail_enabled` | No active multi-region CloudTrail trail | MEDIUM | `CIS AWS Foundations Benchmark 3.1 — CloudTrail Enabled in All Regions` | Manual review |
