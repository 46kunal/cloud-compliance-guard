<#
  Delete everything deploy.ps1 created, so nothing keeps billing.

    .\infra\destroy.ps1

  It empties the artifact bucket first (versioned, so every version and delete marker is removed),
  then deletes the main stack and the artifact stack. DynamoDB data and the audit chain are deleted
  with the stack. Export the evidence bundle from the Reports page first if you want to keep it.
#>
param(
  [string]$Region = "ap-south-1",
  [string]$StackName = "policyguard",
  [string]$ArtifactStack = "policyguard-artifacts"
)
$ErrorActionPreference = "Stop"
$env:AWS_DEFAULT_REGION = $Region

# The anchor bucket holds Object Lock receipts. In GOVERNANCE mode an administrator can delete them with an explicit
# bypass flag. In COMPLIANCE mode nobody can until the retention date, and the stack delete will fail until then.
$anchor = (aws cloudformation describe-stacks --stack-name $StackName --query "Stacks[0].Outputs[?OutputKey=='AnchorBucketName'].OutputValue" --output text 2>$null)
if ($anchor -and $anchor -ne "None") {
  Write-Host "Emptying anchor bucket $anchor (bypassing GOVERNANCE retention)"
  $versions = aws s3api list-object-versions --bucket $anchor --output json | ConvertFrom-Json
  $objects = @()
  foreach ($v in @($versions.Versions) + @($versions.DeleteMarkers)) {
    if ($v) { $objects += @{ Key = $v.Key; VersionId = $v.VersionId } }
  }
  if ($objects.Count -gt 0) {
    $payload = @{ Objects = $objects; Quiet = $true } | ConvertTo-Json -Depth 5 -Compress
    $file = New-TemporaryFile
    Set-Content -Path $file -Value $payload -Encoding ascii
    aws s3api delete-objects --bucket $anchor --bypass-governance-retention --delete "file://$file" | Out-Null
    Remove-Item $file
  }
}

Write-Host "Deleting stack $StackName (about 10 minutes)"
aws cloudformation delete-stack --stack-name $StackName
aws cloudformation wait stack-delete-complete --stack-name $StackName

$bucket = (aws cloudformation describe-stacks --stack-name $ArtifactStack --query "Stacks[0].Outputs[?OutputKey=='ArtifactBucketName'].OutputValue" --output text 2>$null)
if ($bucket -and $bucket -ne "None") {
  Write-Host "Emptying $bucket"
  $versions = aws s3api list-object-versions --bucket $bucket --output json | ConvertFrom-Json
  $objects = @()
  foreach ($v in @($versions.Versions) + @($versions.DeleteMarkers)) {
    if ($v) { $objects += @{ Key = $v.Key; VersionId = $v.VersionId } }
  }
  if ($objects.Count -gt 0) {
    $payload = @{ Objects = $objects; Quiet = $true } | ConvertTo-Json -Depth 5 -Compress
    $file = New-TemporaryFile
    Set-Content -Path $file -Value $payload -Encoding ascii
    aws s3api delete-objects --bucket $bucket --delete "file://$file" | Out-Null
    Remove-Item $file
  }
}
Write-Host "Deleting stack $ArtifactStack"
aws cloudformation delete-stack --stack-name $ArtifactStack
aws cloudformation wait stack-delete-complete --stack-name $ArtifactStack
Write-Host "Done. Check the EC2, VPC and EFS consoles to confirm nothing is left."
