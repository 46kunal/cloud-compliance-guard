# Deploying PolicyGuard on AWS

This guide deploys the whole system into one AWS account in `ap-south-1` (Mumbai) and lists the screenshots
the Cloud Deployment Architecture Report needs. Use a sandbox account.

## Architecture

```text
 Users ──HTTPS──► CloudFront ──HTTP──► Application Load Balancer (2 public subnets, 2 AZs)
                                              │
                          ┌───────────────────┴───────────────────┐
                          ▼                                       ▼
                 EC2 server 1 (private subnet A)         EC2 server 2 (private subnet B)
                 Auto Scaling group, min 2 / max 4 (target: 50% CPU)
                   EBS root volume (encrypted)    EFS /mnt/evidence (shared, encrypted)
                          │                                       │
                          └──────────────► DynamoDB ◄─────────────┘
                                   findings · events · evidence · scans · audit chain
                                              ▲
 EventBridge (every 15 min) ──► Lambda scanner ┘──► SNS email on new HIGH findings
 Cognito user pool: viewer / auditor / admin          CloudWatch alarms · AWS Budget · VPC flow logs
```

| Concern | How it is handled |
| --- | --- |
| Network | Custom VPC. Public subnets route to an internet gateway; private subnets route only through a NAT gateway. DynamoDB and S3 use free gateway endpoints. |
| Access | ALB security group accepts port 80; app servers accept port 5000 only from the ALB; EFS accepts 2049 only from the app servers. No SSH, no key pairs: use Session Manager. IMDSv2 required. |
| Storage | EBS for the OS and app; EFS shared by both servers for saved evidence bundles; DynamoDB for all application data (on-demand billing, point-in-time recovery, encrypted). |
| Login | Amazon Cognito. Groups `viewer`, `auditor`, `admin`. The first admin is invited by email. Passwords are never stored by PolicyGuard. |
| Scanning | A scheduled Lambda, not the web servers. Servers do not scan on their own. The scanner role is read-only plus write access to its own tables. |
| Efficiency | Serverless scanner costs a few cents a month; servers scale on CPU; DynamoDB bills per request. The Infrastructure page compares the scanner against an always-on server (estimate from assumed list prices). |
| Self-check | PolicyGuard scans the account it runs in, including its own resources, which were built to pass its own rules (TLS-only encrypted versioned artifact bucket, 365-day log retention). |

## Prerequisites

* AWS CLI configured (`aws sts get-caller-identity` works) for the target account.
* Python 3.10+ on PATH, PowerShell.
* Two email addresses (can be the same): one gets the Cognito invitation, one gets alerts.

## Deploy

```powershell
.\infra\deploy.ps1 -AdminEmail you@example.com -AlertEmail you@example.com
```

This packages the code, creates the artifact bucket, uploads the zips and creates the main stack (about 10 minutes).
It prints the dashboard URL and the load balancer URL.

1. Open the invitation email, copy the temporary password, and sign in at the dashboard URL (username `pgadmin`).
   You will be asked to choose a permanent password.
2. Confirm the SNS subscription email so alerts reach you.
3. Wait a few minutes after the stack completes: servers install packages on first boot.
4. Create extra users in the Cognito console and add them to the `viewer` or `auditor` group.

**Cost.** The NAT gateway, ALB, two instances and EFS bill by the hour, roughly a few US dollars a day. Build,
capture your screenshots, then run `.\infra\destroy.ps1`. The stack also creates an AWS Budget that emails you at
80% of `MonthlyBudgetUsd` (default 25). Check current prices for your region.

## Local development (no AWS needed for the app)

```powershell
$env:POLICYGUARD_PROFILE = "india"
$env:POLICYGUARD_AUTH = "local"
$env:POLICYGUARD_LOCAL_USERS = "admin:choose-a-password:admin"
$env:POLICYGUARD_SECRET_KEY = "any-long-random-string"
python dashboard/app.py
```

Local login is for development only. Use `POLICYGUARD_BACKEND=dynamodb` with `POLICYGUARD_DYNAMODB_ENDPOINT` to
point at DynamoDB Local if you want to test that backend on your machine.

## Evidence checklist for the report

| Required evidence | Where to capture it | What it should show |
| --- | --- | --- |
| **VPC resource map** | VPC console → your VPC (`policyguard-vpc`) → *Resource map* tab | Public subnets with a route to the internet gateway; private subnets whose route goes to the NAT gateway, not the internet gateway; no public IPs on the servers |
| **Security group chain** | EC2 → Security groups | ALB group open on 80; app group allows 5000 only from the ALB group; EFS group allows 2049 only from the app group |
| **EBS and EFS mounted** | EC2 → instance → *Connect* → Session Manager, then `df -h` and `lsblk` | The root EBS volume and `/mnt/evidence` mounted from the EFS file system |
| **Shared EFS across servers** | Reports page: download an evidence bundle on one server, refresh until the other server answers | The saved file appears in "Saved evidence bundles" from both servers |
| **DynamoDB items** | DynamoDB console → Tables → `policyguard-findings` → *Explore items* | Findings with differently shaped attributes; also `policyguard-finding_evidence` showing nested evidence documents |
| **Load balancer test** | Open the `LoadBalancerUrl` output in a browser and refresh several times | The "Served by i-…" line on the sign-in page alternates between two instance IDs (take two screenshots) |
| **Auto Scaling** | Run `python infra/loadtest.py <DashboardUrl>`; EC2 → Auto Scaling groups → *Activity* | A third instance launching under load, then scaling in afterwards. Dashboard → Infrastructure shows the same |
| **Login and roles** | Sign in as admin, then as a viewer | Viewer gets "no access" on Audit trail and Reports; no "Scan now" button |
| **Scheduled scanner** | Lambda console → `policyguard-scanner` → *Monitor*; EventBridge → rule | Invocations every 15 minutes, with duration and no errors |
| **Alerting** | Create a public bucket in the account, wait for the next scan | An email from SNS and the CloudWatch alarm `policyguard-high-findings` in ALARM state |
| **Security posture** | Dashboard → Frameworks, Findings | India frameworks with open and not-assessed obligations, evidence with hashes |
| **Cost control** | Budgets console | The monthly budget and the 80% alert |

## Admin features added after the first deployment

* **Audit anchors:** `AnchorBucket` (S3 Object Lock) and `AnchorKey` (KMS, RSA 2048, sign and verify) hold signed receipts of
  the audit chain head. `AnchorLockMode` defaults to GOVERNANCE (an administrator can bypass it, and `destroy.ps1` does). In
  COMPLIANCE mode nobody can delete a receipt before `AnchorRetentionDays`, so the stack cannot be fully deleted until then.
* **Adding another AWS account:** on the Accounts page register the account ID, then in that account deploy
  `infra/cloudformation/member-account-role.yaml` with the command the page shows, then press Verify. The role must be named
  `PolicyGuard…` because the scanner's permissions only allow `arn:aws:iam::*:role/PolicyGuard*`.
* **Users:** the Users page manages the Cognito pool through the servers' IAM role, which is allowed only the Cognito admin
  calls it needs on that one pool.
* **Redeploying code without replacing servers:** upload `build/app.zip`, then on each server run
  `aws s3 cp` of the zip, `unzip -o` into `/opt/policyguard`, and `systemctl restart policyguard` through Session Manager.
  Upload `build/scanner.zip` and run `aws lambda update-function-code`.
* **Tamper demo:** `python infra/tamper_demo.py forge`, look at the Audit trail, then `python infra/tamper_demo.py restore`.
* **Demo findings:** `python infra/demo_resources.py create` and `python infra/demo_findings.py create` make deliberately
  weak, empty, clearly named resources; delete them with the matching `delete` commands after the demo. If S3 refuses a bucket
  name you recently deleted, set `POLICYGUARD_DEMO_SUFFIX=m2` and retry.

## Known limits of this deployment

* One NAT gateway in one availability zone. If that zone fails, private servers lose outbound internet (the
  dashboard keeps working for reads through the VPC endpoints). A production design would use one NAT per zone.
* The load balancer accepts HTTP on port 80 from anywhere so the load balancer test works directly. Session cookies
  are marked Secure, so sign-in works through the CloudFront HTTPS URL only. To lock the ALB to CloudFront, restrict
  its security group to the CloudFront origin-facing prefix list.
* The audit chain uses conditional writes so two writers cannot fork it, but anyone with DynamoDB write access can
  still rewrite it. Anchoring the latest hash somewhere they cannot edit (S3 Object Lock or a blockchain) is not part
  of this deployment.
* Remediation stays in dry-run mode in the Lambda (`POLICYGUARD_DRY_RUN=true`).
* The India catalog is a draft built from secondary sources. Confirm clauses against official texts before you
  rely on them.
