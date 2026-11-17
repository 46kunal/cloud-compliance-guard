"""Extra deliberately-weak resources so the dashboard shows every severity during a demo.

    python infra/demo_findings.py create     # run after: python infra/demo_resources.py create
    python infra/demo_findings.py delete

Everything is prefixed "policyguard-demo". Nothing here exposes data: the buckets are empty and the
security group is not attached to any instance. Delete it all after the demo.

Adds:
  - Security group open to the internet on SSH (22)         -> open_admin_ports   HIGH
  - Personal-data bucket in us-east-1 (outside India),
    unencrypted, no TLS policy, no versioning, no logging,
    no lifecycle rule                                       -> data_residency_india, tls_enforcement,
                                                               encryption_at_rest (MEDIUM);
                                                               s3_versioning, s3_access_logging,
                                                               retention_lifecycle (LOW)
"""
import sys

import boto3

PREFIX = "policyguard-demo"
SG_NAME = f"{PREFIX}-sg-ssh-open"


def _account():
    return boto3.client("sts").get_caller_identity()["Account"]


def _home_region():
    return boto3.session.Session().region_name or "ap-south-1"


def create():
    account, region = _account(), _home_region()
    ec2 = boto3.client("ec2", region_name=region)
    vpc = next(v for v in ec2.describe_vpcs()["Vpcs"] if v.get("IsDefault"))["VpcId"]
    existing = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [SG_NAME]}])["SecurityGroups"]
    if existing:
        print(f"[CREATE] security group already exists: {existing[0]['GroupId']}")
    else:
        group = ec2.create_security_group(GroupName=SG_NAME, VpcId=vpc, Description="PolicyGuard demo: SSH open to the internet (not attached to anything)")
        ec2.authorize_security_group_ingress(GroupId=group["GroupId"], IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "demo only"}]}])
        print(f"[CREATE] Open SSH group         {group['GroupId']} ({region})")

    bucket = f"{PREFIX}-us-records-{account}"
    s3 = boto3.client("s3", region_name="us-east-1")
    try:
        s3.create_bucket(Bucket=bucket)
    except Exception as e:
        if "BucketAlreadyOwnedByYou" not in str(e):
            raise
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "data-type", "Value": "user-records"}, {"Key": "handles_personal_data", "Value": "true"}]})
    print(f"[CREATE] Out-of-India bucket    s3://{bucket} (us-east-1, private but weakly configured)")


def delete():
    account, region = _account(), _home_region()
    ec2 = boto3.client("ec2", region_name=region)
    for group in ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [SG_NAME]}])["SecurityGroups"]:
        ec2.delete_security_group(GroupId=group["GroupId"])
        print(f"[DELETE] security group {group['GroupId']}")
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = f"{PREFIX}-us-records-{account}"
    try:
        s3.delete_bucket(Bucket=bucket)
        print(f"[DELETE] bucket {bucket}")
    except Exception as e:
        if "NoSuchBucket" not in str(e):
            print(f"[DELETE] warning: {e}")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "create":
        create()
    elif command == "delete":
        delete()
    else:
        sys.exit("usage: python infra/demo_findings.py create|delete")
