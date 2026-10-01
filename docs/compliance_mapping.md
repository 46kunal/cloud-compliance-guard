# Rule → regulation mapping

Source of truth: `lambdas/rule_engine/framework_mapping.py` (`RULE_TO_CLAUSE`).

| Rule | Detects | Severity | Clause | Auto-remediation |
|---|---|---|---|---|
| `public_storage` | S3 bucket public via bucket policy (not blocked by Public Access Block) | HIGH | GDPR Article 32 — Security of Processing | `close_public_bucket` |
| `wildcard_permission` | IAM policy with `Allow` of `*` or `service:*` on `Resource: *` | HIGH | PCI-DSS Requirement 7 — Restrict Access by Business Need to Know | `revoke_iam_permission` (detach) |
| `encryption_at_rest` | S3 bucket with no default server-side encryption | MEDIUM | PCI-DSS Requirement 3 — Protect Stored Account Data | `enforce_encryption` (AES256) |
| `mfa_required` | IAM user with console password and no MFA device | MEDIUM | PCI-DSS Requirement 8.4 — Multi-Factor Authentication | Manual review |

Related clauses (not encoded, useful for the report): `public_storage` and `encryption_at_rest`
also support GDPR Art. 5(1)(f) (integrity & confidentiality); `wildcard_permission` and
`mfa_required` also support GDPR Art. 32(1)(b) (ongoing confidentiality of processing systems).
