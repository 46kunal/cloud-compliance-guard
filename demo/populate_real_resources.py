"""
Populates real AWS resources for PolicyGuard demonstration purposes.

Resource Requirements:
1. Three S3 buckets tagged data-type=user-records and handles_personal_data=true:
   - Public + Unencrypted
   - Private + Unencrypted
   - Private + Encrypted (Compliant)
2. Two S3 buckets tagged data-type=infra-logs and handles_personal_data=false:
   - Public + Unencrypted (Security-tier finding)
   - Private + Encrypted (Compliant)
3. One Security Group allowing 0.0.0.0/0 on port 22 (SSH).

All resource names are prefixed with 'policyguard-demo-'.
Writes created resource details to demo_resources.json.
"""
import json
import os
import sys
import boto3

PREFIX = "policyguard-demo"


def get_json_file_paths():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [
        os.path.join(base_dir, "demo_resources.json"),
        os.path.join(base_dir, "demo", "demo_resources.json"),
        os.path.abspath("demo_resources.json"),
    ]


def populate():
    try:
        sts = boto3.client("sts")
        account_id = sts.get_caller_identity()["Account"]
    except Exception as e:
        print(f"Error getting AWS account ID (ensure AWS credentials are configured): {e}")
        sys.exit(1)

    region = boto3.session.Session().region_name or "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)

    created_resources = {
        "account_id": account_id,
        "region": region,
        "buckets": [],
        "security_groups": []
    }

    # Helper kwargs for bucket creation outside us-east-1
    bucket_kwargs = {} if region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": region}}

    bucket_configs = [
        # Group 1: user-records (handles_personal_data=true)
        {
            "name": f"{PREFIX}-user-pub-unenc-{account_id}",
            "tags": [{"Key": "data-type", "Value": "user-records"}, {"Key": "handles_personal_data", "Value": "true"}],
            "public": True,
            "encrypted": False,
            "desc": "User records - Public + Unencrypted (High Risk Violation)"
        },
        {
            "name": f"{PREFIX}-user-priv-unenc-{account_id}",
            "tags": [{"Key": "data-type", "Value": "user-records"}, {"Key": "handles_personal_data", "Value": "true"}],
            "public": False,
            "encrypted": False,
            "desc": "User records - Private + Unencrypted (Medium Risk Violation)"
        },
        {
            "name": f"{PREFIX}-user-priv-enc-{account_id}",
            "tags": [{"Key": "data-type", "Value": "user-records"}, {"Key": "handles_personal_data", "Value": "true"}],
            "public": False,
            "encrypted": True,
            "desc": "User records - Private + Encrypted (Compliant)"
        },
        # Group 2: infra-logs (handles_personal_data=false)
        {
            "name": f"{PREFIX}-infra-pub-unenc-{account_id}",
            "tags": [{"Key": "data-type", "Value": "infra-logs"}, {"Key": "handles_personal_data", "Value": "false"}],
            "public": True,
            "encrypted": False,
            "desc": "Infra logs - Public (Security-tier finding)"
        },
        {
            "name": f"{PREFIX}-infra-priv-enc-{account_id}",
            "tags": [{"Key": "data-type", "Value": "infra-logs"}, {"Key": "handles_personal_data", "Value": "false"}],
            "public": False,
            "encrypted": True,
            "desc": "Infra logs - Private + Encrypted (Compliant)"
        }
    ]

    print("=== Populating Demo AWS Resources ===")
    for config in bucket_configs:
        bucket_name = config["name"]
        print(f"\nCreating S3 bucket: {bucket_name} ({config['desc']})...")

        try:
            s3.create_bucket(Bucket=bucket_name, **bucket_kwargs)
        except s3.exceptions.BucketAlreadyOwnedByYou:
            print(f"  Bucket {bucket_name} already exists and owned by you.")
        except Exception as e:
            print(f"  Failed to create bucket {bucket_name}: {e}")
            continue

        # Tagging
        try:
            s3.put_bucket_tagging(
                Bucket=bucket_name,
                Tagging={"TagSet": config["tags"]}
            )
            print(f"  Tags applied: {config['tags']}")
        except Exception as e:
            print(f"  Failed to tag bucket {bucket_name}: {e}")

        # Public access configuration
        if config["public"]:
            try:
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False
                    }
                )
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "PublicReadGetObject",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/*"
                    }]
                }
                s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
                print("  Bucket policy set to Public-Read.")
            except Exception as e:
                print(f"  Warning setting public access: {e}")
        else:
            try:
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True
                    }
                )
                print("  Public access blocked.")
            except Exception as e:
                print(f"  Warning blocking public access: {e}")

        # Encryption configuration
        if config["encrypted"]:
            try:
                s3.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration={
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
                    }
                )
                print("  Default KMS encryption enabled.")
            except Exception as e:
                print(f"  Warning configuring encryption: {e}")
        else:
            print("  Encryption left disabled (unencrypted).")

        created_resources["buckets"].append(bucket_name)

    # 3. Create Security Group with port 22 open to 0.0.0.0/0
    sg_name = f"{PREFIX}-sg-ssh-open"
    print(f"\nCreating Security Group: {sg_name}...")
    try:
        # Find default VPC
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        vpc_id = vpcs["Vpcs"][0]["VpcId"] if vpcs.get("Vpcs") else None

        sg_kwargs = {
            "GroupName": sg_name,
            "Description": "PolicyGuard demo security group with open SSH port"
        }
        if vpc_id:
            sg_kwargs["VpcId"] = vpc_id

        # Check if already exists
        existing_sgs = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [sg_name]}]
        ).get("SecurityGroups", [])

        if existing_sgs:
            sg_id = existing_sgs[0]["GroupId"]
            print(f"  Security group {sg_name} already exists ({sg_id}).")
        else:
            res = ec2.create_security_group(**sg_kwargs)
            sg_id = res["GroupId"]
            print(f"  Created security group {sg_id}.")

            ec2.create_tags(
                Resources=[sg_id],
                Tags=[
                    {"Key": "Name", "Value": sg_name},
                    {"Key": "Project", "Value": "PolicyGuard"}
                ]
            )

        # Inbound SSH rule 0.0.0.0/0
        try:
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Allow open SSH (PolicyGuard Demo)"}]
                }]
            )
            print("  Added inbound rule: TCP port 22 from 0.0.0.0/0.")
        except ec2.exceptions.ClientError as e:
            if "InvalidPermission.Duplicate" in str(e):
                print("  Inbound SSH rule already exists.")
            else:
                print(f"  Warning adding SSH ingress rule: {e}")

        created_resources["security_groups"].append({"sg_id": sg_id, "sg_name": sg_name})

    except Exception as e:
        print(f"Failed to create security group: {e}")

    # Write output file to demo_resources.json
    paths = get_json_file_paths()
    for file_path in paths:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(created_resources, f, indent=2)
            print(f"\nSaved created resources list to: {file_path}")
        except Exception as e:
            print(f"Error writing to {file_path}: {e}")

    print("\n=== Resource Population Complete ===")


if __name__ == "__main__":
    populate()
