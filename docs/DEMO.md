# PolicyGuard demo guide

A 15 to 20 minute talk track for the live deployment. Each section says what to click, what to say, and what is honest
to claim. Sign in at the CloudFront address from the stack outputs.

## 0. Before you start

* Make sure a scan has run recently (Overview shows the finished time). Press **Scan now** as admin if not.
* Have three logins ready to show roles: an admin, an auditor and a viewer (create them on the **Users** page).
* For the tamper demo, run `python infra/tamper_demo.py forge` only when you reach section 6, and `restore` afterwards.

## 1. The problem (1 minute)

Cloud accounts drift into insecure states, and Indian organisations also owe specific duties: CERT-In (logs, six-hour
incident reports), DPDP (security safeguards, breach notices), and sector rules (RBI, SEBI, IRDAI). PolicyGuard scans an
AWS account against those, keeps the evidence, and makes the record hard to rewrite.

**Honest framing:** it checks cloud configuration. A passing result is not a legal compliance determination.

## 2. Overview and findings (3 minutes)

* **Overview:** the score is the share of successfully assessed resources with no open finding. Point at the severity
  split. If a service could not be read, the page says so and the scan is PARTIAL. It never counts unread resources as
  passing.
* **Findings:** filter by severity and framework. The demo account shows **HIGH** (public bucket, wildcard IAM policy,
  SSH open to the internet), **MEDIUM** (no TLS, unencrypted, outside India, no MFA, no CloudTrail) and **LOW**
  (versioning, access logging and lifecycle on personal-data buckets).
* Open **View evidence** on a finding: observed configuration, expected condition, the clause, the collection status and
  a SHA-256 hash of the evidence.

## 3. Frameworks: what is implemented (4 minutes)

Open **Frameworks**. Each card is one obligation, grouped by law.

* **Checked automatically:** 19 checks, from public storage and encryption to flow logs, log retention, backups,
  residency in `ap-south-1` and `ap-south-2`, TLS, root MFA, stale access keys and GuardDuty. They run against S3, IAM,
  EC2, EBS, RDS, DynamoDB, EFS, CloudTrail, CloudWatch Logs and GuardDuty.
* **Verification badges:** six obligations are marked *primary*: the wording was read from the official CERT-In
  directions and FAQs, the RBI payment data circular, SEBI's CSCRF circular and IRDAI's 2023 guidelines. Open
  **What the source says** to show the key points and the link. The DPDP Rules 6 and 7 come from a third-party
  reproduction, and the DPDP Act text could not be retrieved, so those are marked *secondary* or *needs verification*.
  Say this out loud: it is a strength, not a weakness.
* **Duties that are not visible in cloud settings** (consent, notices, grievance, processor contracts, NTP) cannot be
  faked. They show as *Needs attestation* until an admin records the owner and evidence on the **Controls** page.
  Attest two or three live to show the card change to *Attested* with an owner, evidence and a review date.
* **Incidents:** open one (type *Data Breach*, personal data: yes). Show the live **6-hour CERT-In** clock and the
  **72-hour Board** clock, then **Draft reports**. Say clearly that nothing is sent to any regulator.

## 4. Roles and users (2 minutes)

* **Viewer** reads findings. **Auditor** also sees evidence, reports, audit trail, controls, incidents and accounts.
  **Admin** also runs scans and manages users, accounts, controls and incidents.
* **Users** page (admin): create a user (Cognito emails a temporary password), change a role, disable, delete. You cannot
  change or delete yourself, and the last enabled admin cannot be removed. Every change is written to the audit trail.
* Sign in as the viewer in a private window: Audit trail and Reports are refused.

## 5. More than one AWS account (2 minutes)

Open **Accounts**.

* Adding an account is a handshake, and **no access keys are ever typed in**. The admin registers the account ID,
  PolicyGuard generates an **External ID**, and the owner of that account deploys a read-only role from
  `infra/cloudformation/member-account-role.yaml`. **Verify** proves PolicyGuard can assume it.
* Once two accounts have data, the **account picker** in the top bar filters every page.
* Why roles and not keys: short-lived credentials, the owner can end access by deleting the role, every assumption is
  in CloudTrail, and the External ID blocks the confused-deputy attack.
* If you only have one account to show, explain the flow and show the generated command and template.

## 6. The audit trail and the "blockchain" part (4 minutes)

Open **Audit trail**.

**What exists:**

1. **Hash chain (real, live).** Every event stores a SHA-256 hash over its content and the previous hash. Edit, reorder or
   delete any entry and the chain breaks. DynamoDB conditional writes stop two writers forking it.
2. **Anchors (real, live).** After each scan, the latest head hash is written as a receipt to an **S3 Object Lock**
   bucket, so it cannot be changed or deleted until its retention date, and **signed by an AWS KMS key** whose private
   key never leaves KMS. The page re-checks every receipt against the live chain.

**Why anchors matter, live:**

1. Run `python infra/tamper_demo.py forge`. It rewrites one event and recomputes every hash, as an attacker with
   database access would.
2. Refresh the page: **Chain integrity still says VALID** (the old check is fooled), but **Anchor check says MISMATCH**
   and the receipt row explains why.
3. Run `python infra/tamper_demo.py restore`. The anchor check returns to VERIFIED.

**What to claim honestly:**

* This is blockchain-style tamper evidence built from AWS services. It is not a public blockchain and has no
  decentralisation.
* It detects silent rewriting. It does not stop someone with enough permissions from deleting the bucket. In
  GOVERNANCE mode an administrator can bypass the lock. COMPLIANCE mode cannot be bypassed by anyone, but then the stack
  cannot be fully deleted until the retention date.
* The repository also contains a Solidity contract (`blockchain/contracts/AuditAnchor.sol`) and a client
  (`lambdas/audit_logger/blockchain_anchor.py`) for anchoring to a public test network. They are tested only against a
  fake web3 library and have **not been deployed**. Say so.

**How to improve it next:** anchor to a public chain as a second proof (needs a wallet and an RPC provider); anchor
receipts to a second AWS account so one compromised account cannot rewrite both; publish the signing key's public part so
auditors can verify without AWS access; add a periodic verifier that alerts on MISMATCH.

## 7. Cloud architecture (3 minutes)

Open **Infrastructure** and the architecture diagram in `docs/DEPLOYMENT.md`.

* VPC with public and private subnets, ALB across two zones, Auto Scaling servers, EBS and EFS, DynamoDB, a scheduled
  Lambda scanner, Cognito, CloudFront, KMS, S3 Object Lock, SNS and CloudWatch alarms, a budget alert. All defined in
  CloudFormation.
* Refresh the sign-in page on the load balancer address: the instance ID alternates.
* The scanner is serverless, so the cost of scanning is cents a month. The servers scale on CPU.
* PolicyGuard scans its own infrastructure, and the stack was built to pass its own rules.

## 8. Limits to state plainly

* Checks cover configuration, not legal compliance.
* Some wording is not yet confirmed against official texts (DPDP Rules and Act). The UI marks each one.
* The `backup_enabled` check can over-report EBS volumes that are covered by AWS Backup recovery points.
* Remediation stays in dry-run on AWS.
* Login rate limiting is per server.
* The public-chain anchoring is written and unit-tested but not deployed.
