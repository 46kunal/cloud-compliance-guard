"""
Cleanup script to remove all real AWS resources created by demo/populate_real_resources.py.

Reads demo_resources.json and deletes:
- Created S3 buckets (emptying objects and object versions prior to deletion)
- Created Security Groups
- Removes local demo_resources.json files upon completion.
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


def load_demo_resources():
    paths = get_json_file_paths()
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    print(f"Loaded demo resource manifest from: {path}")
                    return data, path
            except Exception as e:
                print(f"Error reading {path}: {e}")
    return None, None


def _ignore_missing(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception as e:
        err_msg = str(e)
        if "NoSuch" not in err_msg and "NotFound" not in err_msg and "InvalidGroup.NotFound" not in err_msg:
            print(f"  Warning: {e}")


def cleanup():
    data, manifest_path = load_demo_resources()
    region = data.get("region") if data else (boto3.session.Session().region_name or "us-east-1")
    s3 = boto3.client("s3", region_name=region)
    s3_resource = boto3.resource("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)

    buckets = data.get("buckets", []) if data else []
    security_groups = data.get("security_groups", []) if data else []

    print("=== Cleaning Up Demo AWS Resources ===")

    # 1. Delete S3 Buckets
    if buckets:
        for bucket_name in buckets:
            print(f"\nDeleting S3 bucket: {bucket_name}...")
            try:
                # Delete objects and versions if any exist
                bucket_obj = s3_resource.Bucket(bucket_name)
                _ignore_missing(bucket_obj.object_versions.delete)
                _ignore_missing(bucket_obj.objects.delete)

                # Delete policy and bucket
                _ignore_missing(s3.delete_bucket_policy, Bucket=bucket_name)
                _ignore_missing(s3.delete_bucket_tagging, Bucket=bucket_name)
                s3.delete_bucket(Bucket=bucket_name)
                print(f"  Deleted bucket {bucket_name}.")
            except Exception as e:
                print(f"  Failed to delete bucket {bucket_name}: {e}")
    else:
        print("No buckets recorded in manifest.")

    # 2. Delete Security Groups
    if security_groups:
        for sg_info in security_groups:
            sg_id = sg_info.get("sg_id") if isinstance(sg_info, dict) else sg_info
            sg_name = sg_info.get("sg_name", sg_id) if isinstance(sg_info, dict) else sg_id
            print(f"\nDeleting Security Group: {sg_name} ({sg_id})...")
            try:
                # Revoke ingress rule first if present
                _ignore_missing(
                    ec2.revoke_security_group_ingress,
                    GroupId=sg_id,
                    IpPermissions=[{
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }]
                )
                ec2.delete_security_group(GroupId=sg_id)
                print(f"  Deleted Security Group {sg_id}.")
            except Exception as e:
                print(f"  Failed to delete Security Group {sg_id}: {e}")
    else:
        print("No security groups recorded in manifest.")

    # 3. Clean up manifest files
    paths = get_json_file_paths()
    for file_path in paths:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"Removed resource manifest file: {file_path}")
            except Exception as e:
                print(f"Failed to remove {file_path}: {e}")

    print("\n=== Cleanup Complete ===")


if __name__ == "__main__":
    cleanup()
