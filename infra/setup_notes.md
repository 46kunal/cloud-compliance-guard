# PolicyGuard — setup & demo runbook

Everything below assumes AWS credentials are already configured (`aws configure`).
Nothing in the local demo needs deployment — the Lambda steps in section 5 are optional.

## 1. Install

```bash
git pull
pip install -r requirements.txt
python -m pytest tests/ -v          # 40 tests, no AWS needed (moto mocks AWS in tests)
aws sts get-caller-identity          # confirm creds/account
```

## 2. Create demo misconfigurations in the account (one command)

```bash
python infra/demo_resources.py create     # public bucket, wildcard IAM policy + role, user without MFA
```

All resources are prefixed `policyguard-demo` and are visible in the S3 and IAM consoles.
The bucket is empty; the user has a random password nobody knows; the wildcard policy is only on
a role assumable from inside this account. Remove everything with `python infra/demo_resources.py delete`.

Note: AWS encrypts new buckets with SSE-S3 by default, but the `encryption_at_rest` rule requires SSE-KMS,
so any bucket on the default setting is reported. The auto-fix applies SSE-KMS.

## 3. Run the pipeline against the account

```bash
python demo/simulate_violation.py --save    # scans the account, prints [DETECT]/[CLASSIFY]/[REMEDIATE]/[AUDIT]
python dashboard/app.py                     # http://127.0.0.1:5000  and  /audit
```

Individual stages (each has a CLI mode that runs the pipeline up to that stage):

```bash
python lambdas/rule_engine/handler.py       # [DETECT]
python lambdas/risk_classifier/handler.py   # [CLASSIFY]
python lambdas/remediation/handler.py       # [REMEDIATE] (dry-run)
python lambdas/audit_logger/handler.py      # [AUDIT]
```

## 4. Live remediation (the safety gate)

Remediation is dry-run by default. A real fix only happens when BOTH are true:

1. `POLICYGUARD_DRY_RUN=false` is set, and
2. the resource ID is in `lambdas/remediation/safety/allowlist.json`.

Paste the allowlist JSON that `demo_resources.py create` printed.

```bash
POLICYGUARD_DRY_RUN=false python demo/simulate_violation.py --save    # bash
# PowerShell:  $env:POLICYGUARD_DRY_RUN="false"; python demo/simulate_violation.py --save
```

Then re-run `python demo/simulate_violation.py` — the public bucket violation is gone.
Actions: `close_public_bucket` (enables Public Access Block), `enforce_encryption` (SSE-KMS default),
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
python infra/demo_resources.py delete
```

`delete` removes every S3 bucket whose name starts with `policyguard-demo-` (emptying it first), so leftovers from earlier demo runs are cleaned too. Security groups named `policyguard-demo*` are only listed; delete them in the EC2 console.
