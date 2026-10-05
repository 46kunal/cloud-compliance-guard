# PolicyGuard — Automated Cloud Compliance & Governance Auditing Platform

**PolicyGuard** scans an AWS account for security misconfigurations, decides for each one whether it is a *privacy* problem (cited under India's DPDP Act 2023) or a *security hygiene* problem (cited under the CIS AWS Foundations Benchmark), shows everything on a live dashboard, can safely auto-fix the riskiest issues, and records every event in a tamper-evident hash-chained audit log.

> Student project for **Advanced Cloud Computing**. Intended for sandbox AWS accounts only — see [Known Limitations](#8-known-limitations).

---

## 1. What it does

| Stage | What happens | Where |
| :--- | :--- | :--- |
| **Detect** | Collects S3 buckets, IAM policies/users, EC2 security groups and the CloudTrail setup via `boto3`, then runs every rule module in `lambdas/rule_engine/rules/` | `lambdas/rule_engine/` |
| **Classify** | Picks the tier from the resource's `handles_personal_data` tag, attaches the DPDP or CIS clause, assigns a severity | `lambdas/tier_classifier.py`, `lambdas/risk_classifier/` |
| **Remediate** | Fixes a few issues automatically — dry-run by default and only for allowlisted resources | `lambdas/remediation/` |
| **Audit** | Appends each event to a SHA-256 hash chain; `verify_chain()` detects any edit | `lambdas/audit_logger/` |
| **Visualize** | Flask dashboard that re-scans the account every 20 s | `dashboard/`, `db/` |

### Rules

| Rule | Detects | Severity | Auto-fix |
| :--- | :--- | :--- | :--- |
| `public_storage` | S3 bucket readable by anyone | HIGH | Enable Block Public Access |
| `wildcard_permission` | IAM policy allowing `*` on `*` | HIGH | Detach policy from users/groups/roles |
| `open_admin_ports` | Security group open to the internet on 22/3389 | HIGH | Manual review |
| `encryption_at_rest` | S3 bucket without SSE-KMS default encryption | MEDIUM | Enable SSE-KMS |
| `mfa_required` | IAM user with console password and no MFA | MEDIUM | Manual review |
| `cloudtrail_enabled` | No active multi-region CloudTrail trail | MEDIUM | Manual review |

Full rule-to-clause table: [`docs/compliance_mapping.md`](docs/compliance_mapping.md).

---

## 2. Architecture

```text
AWS account (S3, IAM, EC2, CloudTrail)
        │  boto3 (read-only scan)
        ▼
 Rule Engine ──► Risk Classifier ──┬──► Remediation (dry-run + allowlist)
                                   │
                                   └──► Audit Logger (SHA-256 hash chain)
                                              │
                                              ▼
                              SQLite ──► Flask dashboard (live re-scan every 20 s)
```

Every `lambdas/*/handler.py` has two entry points: `lambda_handler(event, context)` for AWS Lambda and a `__main__` block for running that stage from the command line. The dashboard's background scanner and `demo/simulate_violation.py` chain the stages **in-process**; the Lambdas are deployable (see `infra/setup_notes.md`) but are not wired together with EventBridge/Step Functions.

More detail: [`docs/architecture.md`](docs/architecture.md).

---

## 3. Folder structure

```text
├── lambdas/      rule_engine, risk_classifier, remediation, audit_logger, tier_classifier.py
├── dashboard/    Flask app, live scanner, templates, static files
├── db/           SQLite schema and helpers
├── demo/         simulate_violation.py (end-to-end run) and demo_script.md (presenter notes)
├── infra/        demo_resources.py (create/delete test resources), IAM policy JSONs, Config rule, setup notes
├── blockchain/   AuditAnchor.sol and Hardhat scripts (optional, see Known Limitations)
├── tests/        pytest suite (moto mocks AWS in memory)
└── docs/         architecture and compliance mapping
```

---

## 4. Tech stack

| Component | Technology |
| :--- | :--- |
| Cloud | AWS S3, IAM, EC2 (security groups), CloudTrail — read via `boto3` |
| Backend | Python 3.10+, Flask, SQLite |
| Frontend | HTML, CSS, vanilla JavaScript |
| Testing | pytest, moto (in-memory AWS) |
| Optional / not deployed | AWS Lambda, AWS Config custom rule, DynamoDB audit table, Solidity + web3.py anchoring |

---

## 5. Setup

### Prerequisites
* Python 3.10+
* AWS CLI configured for a **sandbox** account (`aws configure`) — see `infra/iam/policyguard-dev-user-policy.json` for the permissions the scan needs

### Install and test
```bash
git clone https://github.com/46kunal/cloud-compliance-guard.git
cd cloud-compliance-guard
pip install -r requirements.txt
python -m pytest tests/ -q
```

### Run the demo against a real account
```bash
python infra/demo_resources.py create      # creates clearly-named test resources (policyguard-demo-*)
python demo/simulate_violation.py --save   # scan: [DETECT] [CLASSIFY] [REMEDIATE] [AUDIT]
python dashboard/app.py                    # http://127.0.0.1:5000 (re-scans every 20 s)
python infra/demo_resources.py delete      # clean up
```

Step-by-step presenter notes: [`demo/demo_script.md`](demo/demo_script.md). Lambda/Config deployment and live-remediation steps: [`infra/setup_notes.md`](infra/setup_notes.md).

---

## 6. Compliance frameworks

* **Tier 1 — Privacy (DPDP Act 2023 Sec. 8(5), also GDPR Art. 32).** Applied to resources tagged `handles_personal_data=true` (or `data-type=user-records`). Sec. 8(5) requires "reasonable security safeguards"; PolicyGuard *interprets* that as a set of technical controls (no public exposure, encryption, access control, network exposure, audit logging).
* **Tier 2 — Security Hygiene (CIS AWS Foundations Benchmark).** Applied to everything else.

Each finding gets exactly one citation from exactly one tier, chosen at scan time by the resource's tag. Untagged resources default to Tier 2.

---

## 7. Safety

* Remediation is **dry-run by default**. A live fix needs `POLICYGUARD_DRY_RUN=false` **and** the resource ID in `lambdas/remediation/safety/allowlist.json`; a missing allowlist allows nothing.
* The IAM fix only *detaches* a policy (reversible); it never deletes it.
* Run demos and tests only in dedicated sandbox AWS accounts.

---

## 8. Known Limitations

Stated up front so nothing here is a surprise:

* **One set of credentials does everything.** Locally the same IAM user scans and remediates. Separate least-privilege policies exist in `infra/iam/` for the Lambdas, but the local demo does not use that split.
* **AWS only, one region.** S3 and IAM are account-wide, but security groups and CloudTrail are checked only in the configured region. No Azure/GCP, no multi-account.
* **DPDP classification is tag-driven, not inferred.** Someone must tag each resource `handles_personal_data=true`; PolicyGuard does not look inside buckets. IAM users, security groups and CloudTrail are untagged, so their findings always fall under CIS (Tier 2).
* **Encryption rule is stricter than AWS's default.** It requires SSE-KMS, so buckets using the default SSE-S3 are reported (a deliberate choice; the auto-fix applies SSE-KMS).
* **Not every resource type is covered.** Only customer-managed IAM policies are scanned (not inline or AWS-managed ones); no RDS, EBS or KMS key-rotation checks.
* **Remediation covers three rules.** Public buckets, encryption and wildcard policies. MFA, open ports and CloudTrail are flagged for manual action.
* **The pipeline is not event-driven yet.** There are no EventBridge/Step Functions triggers; the AWS Config custom-rule hookup (`infra/config/`) has not been tested against a real Config recorder, and the DynamoDB audit-table write has not been tested against real DynamoDB (the dashboard uses SQLite).
* **Blockchain anchoring has not been run on a real chain.** `AuditAnchor.sol` has not been compiled or deployed and no transaction has been sent. Only the Python client code is unit-tested, against a faked `web3` (`tests/test_blockchain_anchor.py`). It is called by `demo/simulate_violation.py` but **not** by the dashboard's live scanner.
* **The hash chain is tamper-*evident*, not tamper-*proof*.** Anyone who can write to the database can rewrite every entry and recompute all hashes. The chain only becomes strong once its latest hash is stored somewhere that person cannot edit — which is what the (unrun) blockchain anchor is for.
* **Regulatory citations are an interpretation.** DPDP Sec. 8(5) names no technical controls, and CIS references are not pinned to a single benchmark version.

---

## 9. License / Academic note

PolicyGuard is a student project for **Advanced Cloud Computing**, for educational and demonstration purposes only. It is not intended for production use.
