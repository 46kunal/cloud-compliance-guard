"""
Rule: backup_enabled   (profile: india)
Backups keep data available after an incident (DPDP Rule 6 continuity, SEBI cloud framework, SPDI Rules).
Checks RDS automated backups, DynamoDB point-in-time recovery, EFS automatic backups, and that an EBS
volume has at least one snapshot. AWS Backup recovery points that are not visible as snapshots are not
counted, so EBS can over-report. Not flagged when the backup state could not be read.
"""
PROFILE = "india"


def _personal(resource):
    return str((resource.get("tags") or {}).get("handles_personal_data", "")).lower() in ("true", "1", "yes")


BACKUP_TYPES = ("database", "nosql_table", "file_storage", "block_storage")


def check(resource: dict) -> dict:
    compliant = not (resource.get("resource_type") in BACKUP_TYPES and resource.get("backup_enabled") is False)
    return {"compliant": compliant, "rule": "backup_enabled", "resource_id": resource.get("resource_id", "")}
