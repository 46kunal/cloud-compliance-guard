# Rule → regulation mapping

Source of truth: [`lambdas/rule_engine/framework_mapping.py`](../lambdas/rule_engine/framework_mapping.py) (`PRIVACY_CLAUSE_MAP` & `SECURITY_CONTROL_MAP`).
The full obligation catalog (what the law asks, which checks cover it, what is not yet automated) is
[`compliance/india_catalog.json`](../compliance/india_catalog.json), shown in the dashboard's **Frameworks** page.

> **Status: draft.** A passing check is evidence about configuration only and is not a legal compliance determination.
> The catalog is built from secondary sources (law-firm and vendor summaries); no entry is yet verified against the official
> gazette or circular. Confirm any clause before relying on it.

## How a finding gets its citation

PolicyGuard employs a two-tier compliance architecture:

* **Tier 1 — Privacy:** applied when a resource is tagged `handles_personal_data=true` or `data-type=user-records`.
* **Tier 2 — Security Hygiene:** applied to everything else.

Each individual finding receives exactly one citation, from exactly one tier, determined at scan time by the resource's
`handles_personal_data` tag. The tables below show both possible citations for each rule, not that both apply at once.
Untagged resources default to Tier 2.

## Rule profiles

| Profile | Rules enabled | How to select |
|---|---|---|
| `baseline` (default) | the 6 rules in the baseline tables below | nothing to set |
| `india` | baseline + the 6 India rules in the last table | `POLICYGUARD_PROFILE=india` |

---

### Baseline rules

#### Tier 1 — Privacy (DPDP Act 2023)

| Rule | Detects | Severity | Clause | Auto-remediation |
|---|---|---|---|---|
| `public_storage` | S3 bucket public via bucket policy | HIGH | `DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (also GDPR Art. 32)` | `close_public_bucket` |
| `encryption_at_rest` | S3 bucket without SSE-KMS default encryption | MEDIUM | `DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (also GDPR Art. 32)` | `enforce_encryption` (SSE-KMS) |
| `mfa_required` | IAM user with console access and no MFA device | MEDIUM | `DPDP Act 2023 Sec. 8(5) — Access Control Safeguard` | Manual review |
| `open_admin_ports` | Security Group allowing 0.0.0.0/0 on port 22/3389 | HIGH | `DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (Network Exposure)` | Manual review |
| `wildcard_permission` | IAM policy with `Allow` of `*` (or `service:*`) on `Resource: *` | HIGH | `DPDP Act 2023 Sec. 8(5) — Access Control Safeguard` | `revoke_iam_permission` |
| `cloudtrail_enabled` | No active multi-region CloudTrail trail | MEDIUM | `DPDP Act 2023 Sec. 8(5) — Reasonable Security Safeguards (Audit Logging)` | Manual review |

#### Tier 2 — Security Hygiene (CIS AWS Foundations Benchmark)

| Rule | Detects | Severity | Clause | Auto-remediation |
|---|---|---|---|---|
| `public_storage` | S3 bucket public via bucket policy | HIGH | `CIS AWS Foundations Benchmark — Restrict Public Access to Storage` | `close_public_bucket` |
| `encryption_at_rest` | S3 bucket without SSE-KMS default encryption | MEDIUM | `CIS AWS Foundations Benchmark — Storage Encryption at Rest` | `enforce_encryption` (SSE-KMS) |
| `mfa_required` | IAM user with console access and no MFA device | MEDIUM | `CIS AWS Foundations Benchmark 1.13/1.14 — Multi-Factor Authentication` | Manual review |
| `open_admin_ports` | Security Group allowing 0.0.0.0/0 on port 22/3389 | HIGH | `CIS AWS Foundations Benchmark 4.1/4.2 — Restrict Admin Ports (SSH/RDP)` | Manual review |
| `wildcard_permission` | IAM policy with `Allow` of `*` (or `service:*`) on `Resource: *` | HIGH | `CIS AWS Foundations Benchmark — IAM Least Privilege` | `revoke_iam_permission` |
| `cloudtrail_enabled` | No active multi-region CloudTrail trail | MEDIUM | `CIS AWS Foundations Benchmark 3.1 — CloudTrail Enabled in All Regions` | Manual review |

---

### India profile rules (`POLICYGUARD_PROFILE=india`)

All six are manual review (no auto-remediation). Severity is what `severity_rules.py` assigns.

| Rule | Detects | Severity | Clause if the resource is tagged as personal data (Tier 1) | Clause otherwise (Tier 2) |
|---|---|---|---|---|
| `tls_enforcement` | S3 bucket whose policy does not deny non-TLS requests | MEDIUM | `DPDP Rules 2025 Rule 6 — Encryption of Personal Data in Transit` | `CIS AWS Foundations Benchmark 2.1.1 — Deny HTTP Requests to S3` |
| `s3_versioning` | S3 bucket without versioning | LOW | `DPDP Rules 2025 Rule 6 — Backup and Continuity Safeguard` | `AWS Well-Architected Security — S3 Versioning for Recovery` |
| `data_residency_india` | Data store outside `ap-south-1` / `ap-south-2` (a review pointer, not a legal finding) | MEDIUM | `DPDP Act 2023 Sec. 16 — Transfer Outside India (review pointer)` | `Indian data-localisation guidance (RBI/SEBI/IRDAI) — Indian Regions (review pointer)` |
| `log_retention_180d` | Any CloudWatch log group that expires events sooner than 180 days (account-level finding) | MEDIUM | `CERT-In Directions 2022 — 180-day Log Retention` | `CERT-In Directions 2022 — 180-day Log Retention` |
| `log_retention_365d` | Any CloudWatch log group that expires events sooner than one year (account-level finding) | MEDIUM | `DPDP Rules 2025 Rule 6 — One-year Log Retention` | `DPDP Rules 2025 Rule 6 — One-year Log Retention` |
| `threat_detection_enabled` | No enabled GuardDuty detector (account-level finding) | MEDIUM | `DPDP Rules 2025 Rule 7 — Breach Detection Capability` | `CERT-In Directions 2022 — Incident Detection and 6-hour Reporting Readiness` |

> **Known inconsistency to resolve:** `compliance/india_catalog.json` lists `log_retention_180d` and `log_retention_365d` as
> **HIGH** severity, but `lambdas/risk_classifier/severity_rules.py` classifies them **MEDIUM**. The table above follows the code.
> Decide which is intended and make the two agree.

## Catalog coverage

The catalog (`0.2.0-draft`) holds **19 checks**: 12 *implemented* (the 12 rules above) and 7 *planned* — root account MFA,
stale IAM access keys, VPC flow logs, S3 access logging, log storage in India, backups, and retention/lifecycle policy.

Its **16 obligations** cover DPDP Act 2023, DPDP Rules 2025, CERT-In Directions (2022), RBI payment-data storage, the SEBI cloud
framework, IRDAI guidelines and the IT Act s.43A / SPDI Rules. Obligations that cannot be assessed from cloud configuration (for
example breach notification, consent and NTP clock sync) are shown as **not assessed** rather than as passing.

Each obligation carries a verification status: `primary` (checked against the official text), `secondary` (taken from summaries)
or `needs-verification` (sources disagree or a claim could not be confirmed). Today **6 are `secondary` and 10 are
`needs-verification`; none is `primary`.**
