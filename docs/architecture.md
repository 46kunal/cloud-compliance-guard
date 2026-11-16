# PolicyGuard — architecture (as implemented)

PolicyGuard runs in two modes that share the same scanning code:

* **Local / demo** — a Flask dashboard (optionally with a background scanner) on SQLite. This is what has been run and tested.
* **AWS deployment** — a scheduled scanner Lambda, DynamoDB, and the dashboard on EC2 behind a load balancer, created by
  CloudFormation (`docs/DEPLOYMENT.md`). The templates and Lambda are written and unit-tested, but **the stack has not yet been
  deployed to a real AWS account**.

## Pipeline

```
AWS account (S3, IAM, EC2, CloudTrail, CloudWatch Logs, GuardDuty)
   │  boto3, read-only
   ▼
rule_engine      lambdas/rule_engine/handler.py      → violations   [DETECT]
   │  auto-discovers rules/*.py; each rule has a PROFILE ("baseline" always on, "india" only when enabled)
   ▼
risk_classifier  lambdas/risk_classifier/handler.py  → + severity   [CLASSIFY]
   │   (+ tier / clause from framework_mapping.py)
   ├──► remediation   lambdas/remediation/handler.py  → results     [REMEDIATE]
   │       dry-run default + allowlist gate (safety/)
   ▼
audit_logger     lambdas/audit_logger/hash_chain.py  → hash chain   [AUDIT]
   ▼
db/store.py  (storage facade)
   ├── db/schema.py        SQLite   (default, local)
   └── db/dynamo_store.py  DynamoDB (POLICYGUARD_BACKEND=dynamodb)
   ▼
dashboard/app.py  (Flask: Overview, Frameworks, Findings, Scan history, Infrastructure, Reports, Audit trail)
```

Every Lambda handler has two entry points: `lambda_handler(event, context)` for AWS and a `__main__` block that runs the
pipeline up to that stage locally. `dashboard/scanner.py` (`scan_and_save`) chains the stages in-process and is used by the
dashboard, `demo/simulate_violation.py` and the scheduled scanner Lambda (`lambdas/scanner/handler.py`).

## AWS deployment (written, not yet deployed)

```
Users → CloudFront → ALB → EC2 ×2 (Auto Scaling 2–4, private subnets) ──► DynamoDB
                                   EBS root + shared EFS (evidence bundles)
EventBridge (every 15 min) → scanner Lambda → DynamoDB, CloudWatch metrics, SNS email on new HIGH findings
Cognito user pool: viewer / auditor / admin        CloudWatch alarms · AWS Budget · VPC flow logs
```

Defined in `infra/cloudformation/` and driven by `infra/deploy.ps1` / `destroy.ps1`. Details, cost notes and the evidence
checklist: `docs/DEPLOYMENT.md`.

## Components

| Component | Status | Notes |
|---|---|---|
| Resource collection | Implemented | S3 (public policy status, Public Access Block, SSE-KMS, tags, versioning, TLS-only policy, bucket region), IAM (customer-managed policies, users, MFA), EC2 security groups, CloudTrail, CloudWatch log-group retention, GuardDuty. A failed collection is recorded per service and is never reported as "no findings". |
| Rules | Implemented (12) | Baseline (6): `public_storage`, `encryption_at_rest`, `wildcard_permission`, `mfa_required`, `open_admin_ports`, `cloudtrail_enabled`. India profile (6): `tls_enforcement`, `s3_versioning`, `data_residency_india`, `log_retention_180d`, `log_retention_365d`, `threat_detection_enabled`. |
| Profiles | Implemented | `POLICYGUARD_PROFILE=baseline` (default) or `india`. India rules are skipped unless the profile is `india`. |
| Compliance catalog | Draft | `compliance/india_catalog.json` v0.2.0-draft: 19 checks (12 implemented, 7 planned) and 16 obligations (DPDP Act/Rules, CERT-In, RBI, SEBI, IRDAI, IT Act). Every obligation has a verification status; none is yet `primary`. |
| Risk classifier | Implemented | HIGH: `public_storage`, `wildcard_permission`, `open_admin_ports`. MEDIUM: `encryption_at_rest`, `mfa_required`, `cloudtrail_enabled` and the India rules `tls_enforcement`, `data_residency_india`, `log_retention_180d`, `log_retention_365d`, `threat_detection_enabled`. LOW: `s3_versioning`. |
| Remediation | Implemented | `close_public_bucket`, `enforce_encryption` (SSE-KMS), `revoke_iam_permission` (detach). Every other rule is manual review. Dry-run by default (`POLICYGUARD_DRY_RUN`) plus `allowlist.json`; the scanner Lambda defaults to dry-run. |
| Findings lifecycle | Implemented | Stable finding keys; status `ACTIVE` or `RESOLVED`; per-finding events and per-scan evidence with a SHA-256 hash. History is never deleted. |
| Scan coverage | Implemented | Each scan records resources discovered vs assessed, per-service status and errors. A `FAILED` scan never resolves findings, and resources whose collection failed are excluded from the score. |
| Audit log | Implemented | SHA-256 hash chain from `GENESIS`, `verify_chain`; DynamoDB writes use conditional writes so two writers cannot fork it. |
| Blockchain anchor | Optional, never run | `AuditAnchor.sol` + web3 client; no-op unless `WEB3_RPC_URL`, `ANCHOR_CONTRACT_ADDRESS`, `ANCHOR_PRIVATE_KEY` are set. Not called by the dashboard or scanner. |
| Storage | Implemented | SQLite (default) and DynamoDB behind one facade (`db/store.py`). The DynamoDB code is unit-tested against a mock, not against a real account. |
| Dashboard | Implemented | Flask, 7 pages, CSV and evidence-bundle export, printable report, infrastructure/cost page. |
| Login and roles | Implemented | `POLICYGUARD_AUTH=off\|local\|cognito`. Roles `viewer` < `auditor` < `admin`; only `admin` can trigger a scan; the audit trail and reports need `auditor`. `local` is for development only. |
| Scheduled scanner | Written | `lambdas/scanner/handler.py`, triggered by EventBridge; emits CloudWatch metrics and SNS alerts. |
| AWS Config integration | Implemented | Rule engine calls `config:PutEvaluations` when invoked with a `resultToken`; not tested against a real Config recorder. |
| IaC | Written | CloudFormation (`infra/cloudformation/`), IAM policy JSONs, deploy/destroy scripts. Not yet run in a real account. |

## Data shapes

* **Resource:** `{resource_type, provider, resource_id, is_public, encrypted, permissions, tags}` plus type-specific keys
  (for example `has_console_access` / `mfa_enabled` for `iam_user`).
* **Violation:** `{rule, resource_id, clause, tier, compliant: false}`, plus `severity` after classification.
* **Finding (stored):** `{finding_key, rule, provider, account_scope, resource_type, resource_id, clause, severity, status,
  first_detected, last_detected, resolved_at, remediation}`, with `finding_events` and `finding_evidence` (JSON + SHA-256) per scan.
* **Remediation result:** `{action, resource_id, dry_run, success, message, rule}`.
* **Audit entry:** `{id, timestamp, event_type, details, previous_hash, entry_hash}`;
  `entry_hash = sha256(json.dumps(entry_without_hash, sort_keys=True) + previous_hash)`.

## Known limits

* **Score.** The compliance score is the share of successfully assessed resources with no open finding. It is a
  configuration measure, not a legal compliance determination.
* **Not deployed.** The AWS stack, the Cognito login and the DynamoDB backend have not been run against a real account.
* **No event-driven chain.** There is no EventBridge/Step Functions pipeline between the stages; the scheduled Lambda runs the whole scan in one invocation.
* **Region scope.** Security groups, CloudTrail, CloudWatch and GuardDuty checks cover the configured region only.
* **Coverage.** No RDS, EBS or KMS-key-rotation collectors; only customer-managed IAM policies are scanned. The catalog lists seven further checks as *planned* (root MFA, stale access keys, VPC flow logs, S3 access logging, log location in India, backups, retention/lifecycle).
* **Tamper evidence.** The hash chain detects edits, but anyone with database write access can rewrite it. Anchoring the latest hash elsewhere (S3 Object Lock or a blockchain) is not part of the current deployment.
* **Catalog accuracy.** The India catalog is a draft built from secondary sources and must be confirmed against official texts.
