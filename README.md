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
| **Visualize** | Flask dashboard with login and roles (overview, frameworks, findings, scan history, reports, audit trail). Locally it re-scans every 20 s; on AWS a scheduled Lambda scans and the dashboard only reads | `dashboard/`, `db/`, `lambdas/scanner/` |
| **Store** | SQLite locally, DynamoDB on AWS, behind one interface | `db/store.py`, `db/dynamo_store.py` |

### Rules

| Rule | Detects | Severity | Auto-fix |
| :--- | :--- | :--- | :--- |
| `public_storage` | S3 bucket readable by anyone | HIGH | Enable Block Public Access |
| `wildcard_permission` | IAM policy allowing `*` on `*` | HIGH | Detach policy from users/groups/roles |
| `open_admin_ports` | Security group open to the internet on 22/3389 | HIGH | Manual review |
| `encryption_at_rest` | S3 bucket without SSE-KMS default encryption | MEDIUM | Enable SSE-KMS |
| `mfa_required` | IAM user with console password and no MFA | MEDIUM | Manual review |
| `cloudtrail_enabled` | No active multi-region CloudTrail trail | MEDIUM | Manual review |

### India profile

Set `POLICYGUARD_PROFILE=india` to add rules tied to Indian obligations. The default `baseline` profile keeps the six rules above.

| Rule | Detects | Relates to |
| :--- | :--- | :--- |
| `data_residency_india` | S3 buckets, security groups, EBS volumes, RDS instances, DynamoDB tables and EFS file systems outside `ap-south-1` / `ap-south-2` (a review pointer, not a legal finding) | DPDP s.16, RBI payment data, SEBI CSCRF |
| `tls_enforcement` | S3 bucket policy that does not deny non-TLS requests | DPDP Rule 6, SPDI Rules |
| `log_retention_180d` | CloudWatch log groups that expire logs in under 180 days | CERT-In Direction (iv), IRDAI 2023 guidelines |
| `log_retention_365d` | CloudWatch log groups that expire logs in under 365 days | DPDP Rule 6(1)(e) (not yet in force) |
| `log_location_india` | CloudTrail delivering logs outside Indian regions (a review pointer: CERT-In FAQ Q35 allows copies abroad if producible) | CERT-In, IRDAI, SEBI, RBI |
| `vpc_flow_logs` | VPCs with no active flow log | DPDP Rule 6(1)(c), CERT-In |
| `s3_access_logging` | Personal-data buckets with server access logging off | DPDP Rule 6(1)(c) |
| `retention_lifecycle` | Personal-data buckets with no lifecycle (expiry) rule | DPDP s.8(7) |
| `s3_versioning` | S3 versioning off | DPDP Rule 6(1)(d) continuity |
| `backup_enabled` | RDS without backups, DynamoDB without point-in-time recovery, EFS without backups, EBS volumes with no snapshot | DPDP Rule 6(1)(d), SEBI CSCRF |
| `root_mfa` | Root account without MFA, or with access keys | DPDP Rule 6(1)(b) |
| `stale_access_keys` | Active IAM access keys 90 days old or more (limit is a policy choice) | DPDP Rule 6(1)(b) |
| `threat_detection_enabled` | No enabled GuardDuty detector | DPDP Rule 7, CERT-In 6-hour reporting readiness |

`encryption_at_rest` and `public_storage` also cover RDS, EBS and EFS (and publicly accessible RDS) in this profile.
The personal-data rules (`s3_access_logging`, `retention_lifecycle`) only apply to buckets tagged `handles_personal_data=true`.

The mapping from legal obligations to these checks lives in [`compliance/india_catalog.json`](compliance/india_catalog.json).
Every entry records whether it is in force, how much of it can be checked from configuration, and how well its wording
has been verified. On 17 November 2026, six obligations (CERT-In directions (i), (ii) and (iv), the RBI payment data
circular, the SEBI CSCRF circular and the IRDAI 2023 logging guideline) were checked against the official text and are
marked `primary`, with the sources and key points shown on the Frameworks page. The DPDP Rules (6 and 7) come from a
third-party reproduction and the DPDP Act, the SEBI cloud framework and the IT Act text could not be read, so those
stay `secondary` or `needs-verification`. Measured behaviour of the rules is tested in `tests/test_india_rules.py`
and `tests/test_india_rules_ext.py`.

The scanner role needs extra read permissions for the new checks; they are listed in `infra/iam/` and in the
CloudFormation template. Without them a service shows as partial or failed and its rules are skipped, never passed.

Full rule-to-clause table: [`docs/compliance_mapping.md`](docs/compliance_mapping.md).

### Admin and process features

| Feature | Where | What it does |
| :--- | :--- | :--- |
| Tamper-proof audit anchors | Audit trail | After each scan the chain head hash goes to an S3 Object Lock bucket as a KMS-signed receipt. The page re-checks every receipt, so a fully rewritten chain is flagged (`infra/tamper_demo.py` shows it safely) |
| Monitored accounts | Accounts | Scan other AWS accounts through a read-only cross-account role with a per-account External ID. No keys are stored. An account picker filters every page |
| Users | Users (admin) | Create Cognito logins, change viewer / auditor / admin roles, disable or delete. The last admin is protected and every change is audited |
| Controls register | Controls | An admin records owner, evidence and review date for duties that cannot be read from cloud settings. Frameworks shows them as attested, partly attested or needing attestation |
| Incident clock | Incidents | Starts the CERT-In 6-hour and DPDP 72-hour clocks, and drafts the reports for a person to file. Nothing is sent to a regulator |

A talk track for presenting all of this is in [`docs/DEMO.md`](docs/DEMO.md).

### Running on AWS

[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) covers the CloudFormation deployment (VPC, ALB, Auto Scaling servers,
EBS and EFS, DynamoDB, Cognito login, CloudFront HTTPS, scheduled Lambda scanner), cost control, and the screenshot
checklist for the Cloud Deployment Architecture Report.

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

### Switching the monitored AWS account

The top bar always shows which AWS account is being scanned (for example `651980296015 · us-east-1`). Click it, or open
**AWS account** in the menu, to:

* see the account, its identity, the region and where the credentials come from;
* **connect another account** by entering its access keys (they are checked with AWS first) and switch between the
  accounts you have connected;
* **log out** of an account (scans pause until you connect one again) or return to the default credentials.

Only admins can change the account. Keys typed here are kept in the server's memory only, never written to disk or the
database, and are forgotten when the server restarts. Once two accounts have scan history, every page shows only the active
account's findings. On the AWS deployment the account is fixed by the scanner's IAM role and the page is read-only.

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
* **Accounts entered in the dashboard are not persistent.** Keys typed into the AWS account page live in server memory only (by design) and are lost on restart. Access keys are long-lived secrets: use read-only keys, or better an IAM role.
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
