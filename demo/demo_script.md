# PolicyGuard — presenter script (~6 min, live AWS account)

Everything shown comes from the real AWS account — no hardcoded data. Keep the AWS console open
in one browser tab, the dashboard in another, and a terminal.

## Before the demo
- [ ] `pip install -r requirements.txt` and `python -m pytest tests/ -q` → all green
- [ ] `aws sts get-caller-identity` shows the right account
- [ ] `python infra/demo_resources.py create` (creates the misconfigured test resources; copy the printed allowlist)
- [ ] Delete `db/policyguard.db` for a clean dashboard

## 1. The problem (30 s)
"Cloud breaches are mostly misconfigurations — public buckets, admin-wildcard IAM policies,
users without MFA. PolicyGuard finds them, ranks them against GDPR / PCI-DSS, fixes the safe ones,
and keeps a tamper-evident record of everything it did."

## 2. Show the misconfigurations in the AWS console (1 min)
- **S3** → bucket `policyguard-demo-public-<account>` → *Permissions*: Block public access **Off**, bucket policy `Principal: "*"`. The console shows it as **Publicly accessible**.
- **IAM → Users** → `policyguard-demo-user`: Console access **Enabled**, MFA **Not assigned**.
- **IAM → Policies** → `policyguard-demo-admin-wildcard`: `"Action": "*", "Resource": "*"`, attached to `policyguard-demo-role`.

## 3. Scan the account (1.5 min)
```bash
python demo/simulate_violation.py --save
```
The first line prints the AWS account ID and identity being scanned. Walk through:
- **[DETECT]** — rules are plain Python files in `lambdas/rule_engine/rules/` (policy-as-code). Adding a rule = adding a file.
- **[CLASSIFY]** — severity + the regulation clause broken (e.g. PCI-DSS Req 7).
- **[REMEDIATE]** — DRY-RUN by default. Live fixes need *both* `POLICYGUARD_DRY_RUN=false` *and* the resource in the allowlist. MFA → manual review.
- **[AUDIT]** — every event is SHA-256 hash-chained to the previous one, starting from `GENESIS`.

## 4. Show the scan's activity in the AWS console — CloudTrail (45 s)
**CloudTrail → Event history**, filter *User name* = the IAM user/role you ran the scan as
(events appear within ~5 min). You will see PolicyGuard's real API calls:
`ListBuckets`, `GetBucketPolicyStatus`, `GetBucketEncryption`, `ListPolicies`, `GetPolicyVersion`,
`ListUsers`, `GetLoginProfile`, `ListMFADevices`. Read-only — the dry run changed nothing.

## 5. Dashboard (1 min)
```bash
python dashboard/app.py
```
- Main page: compliance score, violations by severity, regulation, remediation status.
- `/audit`: the hash chain, with integrity status at the top.

Tamper evidence: `python demo/simulate_violation.py --tamper` → editing one entry breaks the chain.

## 6. Live fix, verified in the console (1 min)
Paste the allowlist printed by `demo_resources.py create` into `lambdas/remediation/safety/allowlist.json`, then:
```bash
POLICYGUARD_DRY_RUN=false python demo/simulate_violation.py --save
# PowerShell: $env:POLICYGUARD_DRY_RUN="false"; python demo/simulate_violation.py --save
```
In the console:
- **S3** bucket → *Permissions* → Block public access is now **On**.
- **IAM → Roles** → `policyguard-demo-role` → the wildcard policy is **detached**.
- **CloudTrail** → `PutPublicAccessBlock` and `DetachRolePolicy` events made by PolicyGuard.

Run `python demo/simulate_violation.py` again — those violations are gone; the MFA one remains (manual).

## After the demo
```bash
python infra/demo_resources.py delete
```

## Likely questions
- *Is this real data?* — Yes: the first line of the scan prints the AWS account ID; every call is visible in CloudTrail. The test-suite uses moto (in-memory AWS) only for automated tests.
- *Why not just AWS Config managed rules?* — We add regulation mapping, gated auto-remediation, and a tamper-evident log; the rule engine also runs as a Config custom rule (`infra/config/config-rules.json`).
- *What stops remediation from breaking prod?* — Dry-run default + explicit allowlist, fail-closed if the allowlist is missing; IAM fix only detaches (reversible).
- *Why does encryption_at_rest show 0?* — AWS encrypts all new buckets by default since 2023; the rule still checks it, the account is simply compliant.
- *Is the blockchain required?* — No. The hash chain alone gives tamper evidence; anchoring is optional.
