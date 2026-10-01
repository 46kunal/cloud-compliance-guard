# PolicyGuard — setup & demo runbook

Everything below assumes AWS credentials are already configured (`aws configure`).
Nothing in the local demo needs deployment — the Lambda steps in section 5 are optional.

## 1. Install

```bash
git pull
pip install -r requirements.txt
python -m pytest tests/ -v          # 38 tests, no AWS needed
aws sts get-caller-identity          # confirm creds/account
```

## 2. Run the demo

```bash
# Simulated resources (no AWS calls) — always works
python demo/simulate_violation.py --tamper

# Real AWS account scan (S3 + IAM), store results, then open the dashboard
python demo/simulate_violation.py --live --save
python dashboard/app.py              # http://127.0.0.1:5000  and  /audit

# Seed the dashboard with simulated data instead
python db/seed_data.py
```

Individual stages (each has a CLI mode that runs the pipeline up to that stage on the real account):

```bash
python lambdas/rule_engine/handler.py       # [DETECT]
python lambdas/risk_classifier/handler.py   # [CLASSIFY]
python lambdas/remediation/handler.py       # [REMEDIATE] (dry-run)
python lambdas/audit_logger/handler.py      # [AUDIT]
```

## 3. Create real misconfigurations to detect (optional, use a sandbox account)

Replace `<unique>` with something unique, e.g. your initials + date.

```bash
# Wildcard IAM policy (created but NOT attached to anyone -> harmless)
aws iam create-policy --policy-name PolicyGuardDemoAdmin \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

# IAM user with console access and no MFA (pick your own throwaway password)
aws iam create-user --user-name policyguard-demo-user
aws iam create-login-profile --user-name policyguard-demo-user --password '<TempPassw0rd!>' --password-reset-required

# Public bucket: needs Block Public Access off on the bucket (and account-level BPA off)
aws s3api create-bucket --bucket policyguard-demo-<unique> --region us-east-1
aws s3api put-public-access-block --bucket policyguard-demo-<unique> \
  --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
aws s3api put-bucket-policy --bucket policyguard-demo-<unique> \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policyguard-demo-<unique>/*"}]}'
```

Note: since Jan 2023 every S3 bucket is encrypted (SSE-S3) by default, so `encryption_at_rest`
will usually only fire in the simulated demo.

## 4. Live remediation (the safety gate)

Remediation is dry-run by default. A real fix only happens when BOTH are true:

1. `POLICYGUARD_DRY_RUN=false` is set, and
2. the resource ID is in `lambdas/remediation/safety/allowlist.json`.

```json
{ "allowed_resource_ids": ["policyguard-demo-<unique>", "arn:aws:iam::<ACCOUNT_ID>:policy/PolicyGuardDemoAdmin"] }
```

```bash
POLICYGUARD_DRY_RUN=false python demo/simulate_violation.py --live --save    # bash
# PowerShell:  $env:POLICYGUARD_DRY_RUN="false"; python demo/simulate_violation.py --live --save
```

Then re-run `python demo/simulate_violation.py --live` — the public bucket violation is gone.
Actions: `close_public_bucket` (enables Public Access Block), `enforce_encryption` (AES256 default),
`revoke_iam_permission` (detaches the policy from all users/groups/roles; the policy is kept).
`mfa_required` is never auto-fixed (needs a human device) — reported as manual review.

## 5. Deploy as Lambdas (optional)

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=us-east-1

# One role per function, each with its least-privilege policy from infra/iam/
cat > /tmp/trust.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
JSON
for fn in rule-engine remediation audit; do
  aws iam create-role --role-name policyguard-$fn --assume-role-policy-document file:///tmp/trust.json
  aws iam put-role-policy --role-name policyguard-$fn --policy-name policyguard-$fn \
    --policy-document file://infra/iam/lambda-$fn-policy.json
done
sleep 10   # IAM propagation

# Package (flattened zips — handlers fall back to flat imports)
mkdir -p build
(cd lambdas/rule_engine  && zip -r ../../build/rule_engine.zip  . -x '__pycache__/*')
(cd lambdas/remediation  && zip -r ../../build/remediation.zip  . -x '__pycache__/*')
(cd lambdas/audit_logger && zip -r ../../build/audit_logger.zip . -x '__pycache__/*')

aws lambda create-function --function-name policyguard-rule-engine --runtime python3.12 \
  --handler handler.lambda_handler --zip-file fileb://build/rule_engine.zip --timeout 60 \
  --role arn:aws:iam::$ACCOUNT_ID:role/policyguard-rule-engine
aws lambda create-function --function-name policyguard-remediation --runtime python3.12 \
  --handler handler.lambda_handler --zip-file fileb://build/remediation.zip --timeout 60 \
  --role arn:aws:iam::$ACCOUNT_ID:role/policyguard-remediation
aws dynamodb create-table --table-name PolicyGuardAuditLog \
  --attribute-definitions AttributeName=id,AttributeType=S --key-schema AttributeName=id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
aws lambda create-function --function-name policyguard-audit --runtime python3.12 \
  --handler handler.lambda_handler --zip-file fileb://build/audit_logger.zip --timeout 30 \
  --role arn:aws:iam::$ACCOUNT_ID:role/policyguard-audit \
  --environment Variables={AUDIT_TABLE=PolicyGuardAuditLog}

# Invoke
aws lambda invoke --function-name policyguard-rule-engine out.json && cat out.json
```

AWS Config hookup (requires an active Config recorder in the region):

```bash
aws lambda add-permission --function-name policyguard-rule-engine --statement-id config \
  --action lambda:InvokeFunction --principal config.amazonaws.com
sed "s/REGION/$REGION/; s/ACCOUNT_ID/$ACCOUNT_ID/" infra/config/config-rules.json > build/config-rule.json
aws configservice put-config-rule --config-rule file://build/config-rule.json
```

## 6. Cleanup

```bash
aws iam delete-login-profile --user-name policyguard-demo-user
aws iam delete-user --user-name policyguard-demo-user
aws iam delete-policy --policy-arn arn:aws:iam::$ACCOUNT_ID:policy/PolicyGuardDemoAdmin
aws s3 rb s3://policyguard-demo-<unique> --force
```
