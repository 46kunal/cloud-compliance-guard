"""
Rule: wildcard_permission
Flags IAM policies with an Allow statement granting Action "*" (or "service:*")
on Resource "*" — admin-equivalent, over-permissioned policies.
Expects resource_type "iam_policy" whose "permissions" is the list of policy statements.
"""


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _is_wildcard_statement(statement: dict) -> bool:
    if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
        return False
    actions = _as_list(statement.get("Action"))
    resources = _as_list(statement.get("Resource"))
    has_wild_action = any(a == "*" or str(a).endswith(":*") for a in actions)
    return has_wild_action and "*" in resources


def check(resource: dict) -> dict:
    is_compliant = True
    if resource.get("resource_type") == "iam_policy":
        statements = resource.get("permissions", [])
        is_compliant = not any(_is_wildcard_statement(s) for s in statements)

    return {
        "compliant": is_compliant,
        "rule": "wildcard_permission",
        "resource_id": resource.get("resource_id", ""),
    }
