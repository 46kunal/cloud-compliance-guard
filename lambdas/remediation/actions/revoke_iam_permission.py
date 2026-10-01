"""
Action: revoke_iam_permission
Detaches a wildcard IAM policy (by ARN) from every user, group and role.
The policy itself is kept, so the fix is reversible by re-attaching it.
"""
import boto3

try:
    from lambdas.remediation.safety.dry_run import is_remediation_allowed
except ModuleNotFoundError:
    try:
        from safety.dry_run import is_remediation_allowed
    except ModuleNotFoundError:
        import importlib.util
        import os
        _path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "safety", "dry_run.py")
        _spec = importlib.util.spec_from_file_location("dry_run", _path)
        _mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        is_remediation_allowed = _mod.is_remediation_allowed

ACTION = "revoke_iam_permission"


def remediate(resource_id: str, dry_run: bool = True) -> dict:
    result = {"action": ACTION, "resource_id": resource_id, "dry_run": dry_run, "success": False}

    if dry_run:
        result.update(success=True, message=f"Would detach {resource_id} from all users/groups/roles")
        return result
    if not is_remediation_allowed(resource_id):
        result["message"] = "Skipped: resource not in allowlist"
        return result

    try:
        iam = boto3.client("iam")
        detached = []
        for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=resource_id):
            for u in page.get("PolicyUsers", []):
                iam.detach_user_policy(UserName=u["UserName"], PolicyArn=resource_id)
                detached.append(f"user/{u['UserName']}")
            for g in page.get("PolicyGroups", []):
                iam.detach_group_policy(GroupName=g["GroupName"], PolicyArn=resource_id)
                detached.append(f"group/{g['GroupName']}")
            for r in page.get("PolicyRoles", []):
                iam.detach_role_policy(RoleName=r["RoleName"], PolicyArn=resource_id)
                detached.append(f"role/{r['RoleName']}")
        result.update(success=True, detached=detached, message=f"Detached from {len(detached)} entities")
    except Exception as e:
        result["message"] = f"Error: {e}"
    return result
