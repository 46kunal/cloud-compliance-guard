# PolicyGuard — architecture (as implemented)

```
AWS account (S3, IAM)
   │  boto3 read-only calls
   ▼
rule_engine      lambdas/rule_engine/handler.py      → violations   [DETECT]
   │  auto-discovers rules/*.py (check(resource) -> dict)
   ▼
risk_classifier  lambdas/risk_classifier/handler.py  → + severity   [CLASSIFY]
   │
   ├──► remediation   lambdas/remediation/handler.py  → results     [REMEDIATE]
   │       dry-run default + allowlist gate (safety/)
   ▼
audit_logger     lambdas/audit_logger/handler.py     → hash chain   [AUDIT]
   │  SHA-256 chain from "GENESIS"; optional DynamoDB + optional on-chain anchor
   ▼
db/schema.py (SQLite)  ──►  dashboard/app.py (Flask: /, /audit, /api/*)
```

Every Lambda handler has two entry points: `lambda_handler(event, context)` for AWS and a
`__main__` block that runs the pipeline up to that stage locally. `demo/simulate_violation.py`
chains all four stages in-process.

## Components

| Component | Status | Notes |
|---|---|---|
| Resource collection | Implemented | S3: public policy status, Public Access Block, default encryption. IAM: customer-managed policies (default version statements), users (console login profile, MFA devices). |
| Rules | Implemented (4) | `public_storage`, `encryption_at_rest`, `wildcard_permission`, `mfa_required`. |
| Risk classifier | Implemented | HIGH: public_storage, wildcard_permission. MEDIUM: encryption_at_rest, mfa_required. |
| Remediation | Implemented | `close_public_bucket`, `enforce_encryption`, `revoke_iam_permission` (detach). MFA → manual review. |
| Safety | Implemented | `DRY_RUN` (env `POLICYGUARD_DRY_RUN`), `allowlist.json`, fails closed. |
| Audit log | Implemented | Hash chain + `verify_chain`; DynamoDB write when `AUDIT_TABLE` is set. |
| Blockchain anchor | Optional | `AuditAnchor.sol` + web3 call; no-op unless `WEB3_RPC_URL`, `ANCHOR_CONTRACT_ADDRESS`, `ANCHOR_PRIVATE_KEY` are set. |
| Dashboard | Implemented | Flask + SQLite, JSON API, auto-refresh. |
| AWS Config integration | Implemented | Rule engine calls `config:PutEvaluations` (account-level) when invoked with a `resultToken`. |
| IaC | Partial | IAM least-privilege policies + Config rule JSON + CLI runbook (`infra/setup_notes.md`); no CloudFormation/Terraform. |

## Data shapes

- Resource: `{resource_type, provider, resource_id, is_public, encrypted, permissions, tags}`
  (+ `has_console_access`, `mfa_enabled` for `iam_user`).
- Violation: `{rule, resource_id, clause, compliant: false}` (+ `severity` after classification).
- Remediation result: `{action, resource_id, dry_run, success, message, rule}`.
- Audit entry: `{id, timestamp, event_type, details, previous_hash, entry_hash}`;
  `entry_hash = sha256(json.dumps(entry_without_hash, sort_keys=True) + previous_hash)`.

## Known limits

- Compliance score is a flat penalty (HIGH 15 / MEDIUM 8 / LOW 3) — not a per-framework pass rate.
- Lambdas are not chained by Step Functions/EventBridge; the local demo chains them in-process.
- EC2/KMS collectors are not implemented (the rule contract supports adding them).
