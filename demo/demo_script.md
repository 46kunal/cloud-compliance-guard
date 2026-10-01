# PolicyGuard — presenter script (~5 min)

## Before the demo
- [ ] `pip install -r requirements.txt` and `python -m pytest tests/ -q` → all green
- [ ] (live) `aws sts get-caller-identity` works; demo misconfigs created (infra/setup_notes.md §3)
- [ ] Delete `db/policyguard.db` for a clean dashboard
- [ ] Two terminals open + browser on http://127.0.0.1:5000

## 1. The problem (30 s)
"Cloud breaches are mostly misconfigurations — public buckets, admin-wildcard IAM policies,
users without MFA. PolicyGuard finds them, ranks them against GDPR / PCI-DSS, fixes the safe ones,
and keeps a tamper-evident record of everything it did."

## 2. Detection → classification → remediation → audit (2 min)
```bash
python demo/simulate_violation.py --live --save      # or without --live for simulated data
```
Walk through each block of output:
- **[DETECT]** — rules are plain Python files in `lambdas/rule_engine/rules/` (policy-as-code). Adding a rule = adding a file.
- **[CLASSIFY]** — each violation gets a severity and the regulation clause it breaks (e.g. PCI-DSS Req 7).
- **[REMEDIATE]** — note DRY-RUN. Live fixes need *both* `POLICYGUARD_DRY_RUN=false` *and* the resource in the allowlist. MFA is flagged for manual review — you cannot auto-enrol a human.
- **[AUDIT]** — every event is SHA-256 hash-chained to the previous one, starting from `GENESIS`.

## 3. Tamper evidence (45 s)
```bash
python demo/simulate_violation.py --tamper
```
"I edit one historical entry's severity from HIGH to LOW — verification immediately fails. You can't quietly rewrite the audit trail."

## 4. Dashboard (1 min)
```bash
python dashboard/app.py
```
- Main page: compliance score, violations by severity, regulation, remediation status.
- `/audit`: the hash chain, with integrity status at the top.

## 5. Live fix (optional, 45 s)
Add the demo bucket to `lambdas/remediation/safety/allowlist.json`, then:
```bash
POLICYGUARD_DRY_RUN=false python demo/simulate_violation.py --live --save
python demo/simulate_violation.py --live
```
"The public-bucket violation is gone — and the fix itself is in the audit trail."

## Likely questions
- *Why not just AWS Config managed rules?* — We add regulation mapping, gated auto-remediation, and a tamper-evident log; the rule engine also runs as a Config custom rule (`infra/config/config-rules.json`).
- *What stops remediation from breaking prod?* — Dry-run default + explicit allowlist, fail-closed if the allowlist is missing; IAM fix only detaches (reversible).
- *Is the blockchain required?* — No. The hash chain alone gives tamper evidence; anchoring the latest hash on-chain (optional) proves the chain head existed at a point in time.
