"""
Safety layer for remediation.

DRY_RUN defaults to True. A remediation only mutates AWS when BOTH:
  1. dry_run is False (set POLICYGUARD_DRY_RUN=false to flip the default), and
  2. the resource_id is listed in allowlist.json ("allowed_resource_ids").
"""
import json
import os

DRY_RUN = os.environ.get("POLICYGUARD_DRY_RUN", "true").strip().lower() != "false"

ALLOWLIST_PATH = os.environ.get(
    "POLICYGUARD_ALLOWLIST",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowlist.json"),
)


def load_allowlist(path: str = None) -> set:
    try:
        with open(path or ALLOWLIST_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get("allowed_resource_ids", []))
    except (OSError, ValueError):
        # Missing/corrupt allowlist = nothing allowed (fail closed)
        return set()


def is_remediation_allowed(resource_id: str) -> bool:
    return bool(resource_id) and resource_id in load_allowlist()
