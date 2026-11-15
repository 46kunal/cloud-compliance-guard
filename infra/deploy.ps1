<#
  Deploy PolicyGuard to AWS (run from the repository root in PowerShell).

  Usage:
    .\infra\deploy.ps1 -AdminEmail you@example.com -AlertEmail you@example.com

  What it does:
    1. Builds build\app.zip and build\scanner.zip
    2. Creates the artifact bucket stack (policyguard-artifacts)
    3. Uploads both zips
    4. Creates the main stack (policyguard): VPC, ALB, Auto Scaling servers, EFS, DynamoDB, Cognito, Lambda
    5. Prints the URLs

  It creates billable resources (NAT gateway, ALB, EC2, EFS). Run .\infra\destroy.ps1 when you finish.
  Requires: AWS CLI configured for the target account, and Python on PATH.
#>
param(
  [Parameter(Mandatory = $true)][string]$AdminEmail,
  [Parameter(Mandatory = $true)][string]$AlertEmail,
  [string]$Region = "ap-south-1",
  [string]$StackName = "policyguard",
  [string]$ArtifactStack = "policyguard-artifacts",
  [string]$Profile = "india",
  [int]$MonthlyBudgetUsd = 25
)
$ErrorActionPreference = "Stop"
$env:AWS_DEFAULT_REGION = $Region

function Run-Aws { & aws @args; if ($LASTEXITCODE -ne 0) { throw "aws $($args -join ' ') failed" } }

Write-Host "Account:" -NoNewline
Run-Aws sts get-caller-identity --query Account --output text

Write-Host "1/5 Packaging"
python infra/package.py
if ($LASTEXITCODE -ne 0) { throw "packaging failed" }

Write-Host "2/5 Artifact bucket"
Run-Aws cloudformation deploy --stack-name $ArtifactStack --template-file infra/cloudformation/artifacts.yaml --no-fail-on-empty-changeset
$bucket = (aws cloudformation describe-stacks --stack-name $ArtifactStack --query "Stacks[0].Outputs[?OutputKey=='ArtifactBucketName'].OutputValue" --output text)

Write-Host "3/5 Uploading zips to $bucket"
Run-Aws s3 cp build/app.zip "s3://$bucket/app.zip"
Run-Aws s3 cp build/scanner.zip "s3://$bucket/scanner.zip"

Write-Host "4/5 Main stack (about 10 minutes)"
Run-Aws cloudformation deploy --stack-name $StackName --template-file infra/cloudformation/policyguard.yaml `
  --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset --parameter-overrides `
  "ArtifactBucket=$bucket" "AdminEmail=$AdminEmail" "AlertEmail=$AlertEmail" "Profile=$Profile" "MonthlyBudgetUsd=$MonthlyBudgetUsd"

Write-Host "5/5 Outputs"
Run-Aws cloudformation describe-stacks --stack-name $StackName --query "Stacks[0].Outputs" --output table
Write-Host ""
Write-Host "Next: check $AdminEmail for the Cognito invitation, and $AlertEmail to confirm the SNS subscription."
Write-Host "Servers need a few minutes after the stack finishes to install and pass health checks."
