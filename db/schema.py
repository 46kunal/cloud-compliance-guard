"""SQLite persistence and safe, additive migrations for PolicyGuard."""
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get(
    "POLICYGUARD_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "policyguard.db"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
    resources_scanned INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    clause TEXT,
    severity TEXT,
    remediation TEXT,
    detected_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_key TEXT NOT NULL UNIQUE,
    rule TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT 'aws',
    account_scope TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    clause TEXT,
    severity TEXT,
    status TEXT NOT NULL,
    first_detected TEXT NOT NULL,
    last_detected TEXT NOT NULL,
    resolved_at TEXT,
    remediation TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS finding_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    scan_id INTEGER,
    event_type TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT,
    occurred_at TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(finding_id) REFERENCES findings(id),
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS finding_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(id),
    FOREIGN KEY(scan_id) REFERENCES scans(id),
    UNIQUE(finding_id, scan_id)
);
CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scan_resources (
    scan_id INTEGER NOT NULL,
    resource_key TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    service TEXT NOT NULL,
    PRIMARY KEY (scan_id, resource_key),
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
"""

SCAN_COLUMNS = {
    "started_at": "TEXT", "completed_at": "TEXT", "status": "TEXT NOT NULL DEFAULT 'COMPLETED'",
    "account_scope": "TEXT NOT NULL DEFAULT 'legacy'", "region_scope": "TEXT NOT NULL DEFAULT 'legacy'",
    "resources_discovered": "INTEGER NOT NULL DEFAULT 0", "resources_assessed": "INTEGER NOT NULL DEFAULT 0",
    "findings_detected": "INTEGER NOT NULL DEFAULT 0", "services_scanned": "TEXT NOT NULL DEFAULT '[]'",
    "service_statuses": "TEXT NOT NULL DEFAULT '{}'", "collection_errors": "TEXT NOT NULL DEFAULT '[]'",
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _resource_type(rule):
    return {"public_storage": "object_storage", "encryption_at_rest": "object_storage",
            "wildcard_permission": "iam_policy", "mfa_required": "iam_user",
            "open_admin_ports": "security_group", "cloudtrail_enabled": "cloudtrail_config"}.get(rule, "unknown")


def stable_finding_key(rule, provider, account_scope, resource_type, resource_id):
    identity = [rule, provider or "aws", account_scope or "default", resource_type or "unknown", resource_id]
    return hashlib.sha256(json.dumps(identity, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _migrate(conn):
    conn.executescript(SCHEMA)
    present = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    for name, definition in SCAN_COLUMNS.items():
        if name not in present:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {definition}")
    # Preserve the old scans and give them explicit legacy metadata. No existing row is removed.
    legacy_coverage_error = json.dumps([{"service": "scan", "message": "Coverage metadata was unavailable in this legacy scan"}])
    conn.execute("UPDATE scans SET status='PARTIAL',resources_assessed=0,service_statuses='{}',services_scanned='[]',collection_errors=? WHERE account_scope='legacy' AND started_at IS NULL",
                 (legacy_coverage_error,))
    conn.execute("UPDATE scans SET started_at=COALESCE(started_at, scanned_at), completed_at=COALESCE(completed_at, scanned_at), resources_discovered=CASE WHEN resources_discovered=0 THEN resources_scanned ELSE resources_discovered END WHERE started_at IS NULL")

    # Import the latest legacy snapshot once. Old violation rows remain untouched for audit/history.
    marker = conn.execute("SELECT 1 FROM schema_migrations WHERE name='finding_lifecycle_v1'").fetchone()
    if not marker:
        rows = conn.execute("SELECT rule, resource_id, clause, severity, remediation, detected_at FROM violations ORDER BY id").fetchall()
        for row in rows:
            rule, resource_id, clause, severity, remediation, detected_at = row
            account = "legacy"
            rtype = _resource_type(rule)
            key = stable_finding_key(rule, "aws", account, rtype, resource_id)
            conn.execute("INSERT OR IGNORE INTO findings (finding_key,rule,provider,account_scope,resource_type,resource_id,clause,severity,status,first_detected,last_detected,remediation) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                         (key, rule, "aws", account, rtype, resource_id, clause, severity, "ACTIVE", detected_at or _now(), detected_at or _now(), remediation or "{}"))
            finding = conn.execute("SELECT id FROM findings WHERE finding_key=?", (key,)).fetchone()
            conn.execute("INSERT INTO finding_events (finding_id,event_type,to_status,occurred_at,details) VALUES (?,?,?,?,?)",
                         (finding[0], "MIGRATED_LEGACY", "ACTIVE", detected_at or _now(), json.dumps({"source": "violations"})))
        conn.execute("INSERT OR IGNORE INTO schema_migrations(name,applied_at) VALUES('finding_lifecycle_v1',?)", (_now(),))
    conn.commit()


def connect(path: str = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _migrate(conn)
    return conn


def begin_scan(conn, started_at=None, account_scope="configured AWS account", region_scope="configured region"):
    started_at = started_at or _now()
    with conn:
        cur = conn.execute("INSERT INTO scans (scanned_at,resources_scanned,started_at,status,account_scope,region_scope) VALUES (?,0,?,'RUNNING',?,?)",
                            (started_at, started_at, account_scope, region_scope))
    return cur.lastrowid


def save_scan(conn, resources_scanned: int, classified: list, remediation: list, entries: list,
              *, scan_id=None, started_at=None, status="PARTIAL", account_scope="configured AWS account",
              region_scope="configured region", resources_assessed=None, services_scanned=None,
              service_statuses=None, collection_errors=None, allow_resolve=True, assessed_resource_records=None,
              evidence_records=None):
    """Persist findings/events without deleting lifecycle history; retain legacy audit rows."""
    now = _now()
    started_at = started_at or now
    by_key = {(r.get("rule"), r.get("resource_id")): r for r in remediation}
    detected = {(v.get("rule"), v.get("resource_id")) for v in classified}
    with conn:
        if scan_id is None:
            cur = conn.execute("INSERT INTO scans (scanned_at,resources_scanned) VALUES (?,?)", (now, resources_scanned))
            scan_id = cur.lastrowid
        conn.execute("UPDATE scans SET scanned_at=?, resources_scanned=?, started_at=COALESCE(?,started_at), completed_at=?, status=?, account_scope=?, region_scope=?, resources_discovered=?, resources_assessed=?, findings_detected=?, services_scanned=?, service_statuses=?, collection_errors=? WHERE id=?",
                     (now, resources_scanned, started_at, now, status, account_scope, region_scope,
                      resources_scanned, resources_assessed if resources_assessed is not None else 0,
                      len(classified), json.dumps(services_scanned or []), json.dumps(service_statuses or {}),
                      json.dumps(collection_errors or []), scan_id))
        conn.executemany(
            "INSERT OR IGNORE INTO scan_resources (scan_id,resource_key,resource_id,resource_type,service) VALUES (?,?,?,?,?)",
            [(scan_id, stable_finding_key("resource", "aws", account_scope, r.get("resource_type"), r.get("resource_id")),
              r.get("resource_id", ""), r.get("resource_type", "unknown"),
              {"object_storage": "s3", "iam_policy": "iam", "iam_user": "iam", "security_group": "ec2", "cloudtrail_config": "cloudtrail"}.get(r.get("resource_type"), "unknown"))
             for r in assessed_resource_records or []],
        )

        # Existing unresolved findings are matched by stable rule + resource identity + AWS account scope.
        for violation in classified:
            rule, resource_id = violation["rule"], violation["resource_id"]
            provider = violation.get("provider", "aws")
            account = violation.get("account_scope", account_scope)
            resource_type = violation.get("resource_type", _resource_type(rule))
            key = stable_finding_key(rule, provider, account, resource_type, resource_id)
            row = conn.execute("SELECT * FROM findings WHERE finding_key=?", (key,)).fetchone()
            # Migrate a matching legacy key into the current account identity on first observation.
            if row is None and account != "legacy":
                legacy_key = stable_finding_key(rule, provider, "legacy", resource_type, resource_id)
                legacy = conn.execute("SELECT * FROM findings WHERE finding_key=?", (legacy_key,)).fetchone()
                if legacy:
                    conn.execute("UPDATE findings SET finding_key=?,account_scope=? WHERE id=?", (key, account, legacy["id"]))
                    row = conn.execute("SELECT * FROM findings WHERE id=?", (legacy["id"],)).fetchone()
            remediation_json = json.dumps(by_key.get((rule, resource_id), {}))
            if row is None:
                cur = conn.execute("INSERT INTO findings (finding_key,rule,provider,account_scope,resource_type,resource_id,clause,severity,status,first_detected,last_detected,remediation) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                   (key, rule, provider, account, resource_type, resource_id, violation.get("clause"), violation.get("severity"), "NEW", now, now, remediation_json))
                fid = cur.lastrowid
                conn.execute("INSERT INTO finding_events (finding_id,scan_id,event_type,from_status,to_status,occurred_at,details) VALUES (?,?, 'DETECTED',NULL,'NEW',?,?)",
                             (fid, scan_id, now, json.dumps(violation)))
            else:
                old_status = row["status"]
                source_service = {"object_storage": "s3", "iam_policy": "iam", "iam_user": "iam",
                                  "security_group": "ec2", "cloudtrail_config": "cloudtrail"}.get(resource_type)
                source_assessed = (service_statuses or {}).get(source_service, {}).get("status") == "SUCCESS"
                if old_status == "RESOLVED":
                    new_status = "REOPENED"
                elif old_status == "NEW":
                    new_status = "ACTIVE" if source_assessed else "NEW"
                elif old_status == "REOPENED":
                    new_status = "ACTIVE" if source_assessed else "REOPENED"
                else:
                    new_status = "ACTIVE"
                conn.execute("UPDATE findings SET status=?,last_detected=?,resolved_at=NULL,clause=?,severity=?,remediation=? WHERE id=?",
                             (new_status, now, violation.get("clause"), violation.get("severity"), remediation_json, row["id"]))
                if new_status != old_status:
                    event = "REOPENED" if new_status == "REOPENED" else "CONFIRMED"
                    conn.execute("INSERT INTO finding_events (finding_id,scan_id,event_type,from_status,to_status,occurred_at,details) VALUES (?,?,?,?,?,?,?)",
                                 (row["id"], scan_id, event, old_status, new_status, now, json.dumps(violation)))

        if allow_resolve:
            for row in conn.execute("SELECT * FROM findings WHERE status IN ('NEW','ACTIVE','REOPENED')").fetchall():
                # A missing finding may resolve only if its collector succeeded in this scan.
                service = {"object_storage": "s3", "iam_policy": "iam", "iam_user": "iam",
                           "security_group": "ec2", "cloudtrail_config": "cloudtrail"}.get(row["resource_type"])
                if service and (service_statuses or {}).get(service, {}).get("status") == "SUCCESS" and row["account_scope"] == account_scope:
                    was_present = (row["rule"], row["resource_id"]) in detected
                    if not was_present:
                        conn.execute("UPDATE findings SET status='RESOLVED',resolved_at=? WHERE id=?", (now, row["id"]))
                        conn.execute("INSERT INTO finding_events (finding_id,scan_id,event_type,from_status,to_status,occurred_at,details) VALUES (?,?, 'RESOLVED',?,'RESOLVED',?,?)",
                                     (row["id"], scan_id, row["status"], now, json.dumps({"reason": "absent in successfully assessed service scope"})))

        conn.executemany(
            "INSERT INTO audit_log (id,timestamp,event_type,details,previous_hash,entry_hash) VALUES (?,?,?,?,?,?)",
            [(e["id"], e["timestamp"], e["event_type"], json.dumps(e["details"]), e["previous_hash"], e["entry_hash"]) for e in entries],
        )
        # Preserve the legacy table and API compatibility; it is no longer the lifecycle source of truth.
        conn.executemany(
            "INSERT INTO violations (rule,resource_id,clause,severity,remediation,detected_at) VALUES (?,?,?,?,?,?)",
            [(v["rule"], v["resource_id"], v.get("clause"), v.get("severity"),
              json.dumps(by_key.get((v["rule"], v["resource_id"]), {})), now) for v in classified],
        )
        if evidence_records:
            from dashboard.evidence import canonical_evidence
            for record in evidence_records:
                rule, resource_id = record.get("rule"), record.get("resource_id")
                evidence_payload = record.get("evidence") or {}
                key = stable_finding_key(
                    rule, evidence_payload.get("provider", "aws"), account_scope,
                    evidence_payload.get("resource_type", "unknown"), resource_id,
                )
                finding = conn.execute(
                    "SELECT id,status FROM findings WHERE finding_key=?", (key,)
                ).fetchone()
                if not finding:
                    continue
                evidence = dict(record.get("evidence") or {})
                evidence["finding_id"] = finding["id"]
                evidence["lifecycle_status"] = finding["status"]
                evidence["scan_status"] = conn.execute(
                    "SELECT status FROM scans WHERE id=?", (scan_id,)
                ).fetchone()[0]
                payload, digest = canonical_evidence(evidence)
                conn.execute(
                    "INSERT OR IGNORE INTO finding_evidence (finding_id,scan_id,evidence_json,evidence_sha256) VALUES (?,?,?,?)",
                    (finding["id"], scan_id, payload, digest),
                )
    return scan_id


def get_violations(conn) -> list:
    rows = conn.execute("SELECT * FROM findings WHERE status != 'RESOLVED' ORDER BY id").fetchall()
    return [{**dict(r), "remediation": json.loads(r["remediation"] or "{}"), "detected_at": r["first_detected"]} for r in rows]


def get_findings(conn, include_resolved=True):
    clause = "" if include_resolved else " WHERE f.status != 'RESOLVED'"
    rows = conn.execute(
        f"""SELECT f.*,
                   EXISTS(SELECT 1 FROM finding_evidence e WHERE e.finding_id=f.id) AS evidence_available
            FROM findings f{clause} ORDER BY f.id DESC"""
    ).fetchall()
    return [{**dict(r), "evidence_available": bool(r["evidence_available"]),
             "remediation": json.loads(r["remediation"] or "{}")} for r in rows]


def get_finding_events(conn, finding_id=None):
    if finding_id is None:
        rows = conn.execute("SELECT * FROM finding_events ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM finding_events WHERE finding_id=? ORDER BY id", (finding_id,)).fetchall()
    return [{**dict(r), "details": json.loads(r["details"] or "{}")} for r in rows]


def get_finding_evidence(conn, finding_id):
    """Return persisted evidence snapshots for exactly one finding, oldest first."""
    rows = conn.execute(
        """SELECT e.id AS evidence_id,e.finding_id,e.scan_id,e.evidence_json,e.evidence_sha256,
                  s.status AS scan_status,s.account_scope,s.region_scope
           FROM finding_evidence e JOIN scans s ON s.id=e.scan_id
           WHERE e.finding_id=? ORDER BY e.id""", (finding_id,)
    ).fetchall()
    result = []
    for row in rows:
        item = json.loads(row["evidence_json"])
        item.update({"evidence_id": row["evidence_id"], "finding_id": row["finding_id"],
                     "scan_id": row["scan_id"], "scan_status": row["scan_status"],
                     "account_scope": item.get("account_scope") or row["account_scope"],
                     "region_scope": item.get("region_scope") or row["region_scope"],
                     "evidence_sha256": row["evidence_sha256"]})
        result.append(item)
    return result


def get_audit_log(conn) -> list:
    rows = conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
    fields = ("id", "timestamp", "event_type", "details", "previous_hash", "entry_hash")
    return [{k: (json.loads(r[k]) if k == "details" else r[k]) for k in fields} for r in rows]


def get_latest_scan(conn):
    row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    result = dict(row)
    defaults = {"services_scanned": [], "service_statuses": {}, "collection_errors": []}
    for key, fallback in defaults.items():
        raw = result.get(key)
        try:
            value = json.loads(raw) if raw else fallback
        except (TypeError, ValueError) as error:
            raise ValueError(f"Stored scan field '{key}' is not valid JSON") from error
        if not isinstance(value, type(fallback)):
            raise ValueError(f"Stored scan field '{key}' has an invalid shape")
        result[key] = value

    valid_scan_states = {"RUNNING", "COMPLETED", "PARTIAL", "FAILED"}
    status = str(result.get("status") or "").upper()
    if status not in valid_scan_states:
        raise ValueError("Stored scan has an unsupported status")
    result["status"] = status

    valid_service_states = {"SUCCESS", "PARTIAL", "FAILED", "NOT_SCANNED"}
    for service, detail in result["service_statuses"].items():
        if not isinstance(service, str) or not isinstance(detail, dict):
            raise ValueError("Stored service collection metadata has an invalid shape")
        service_status = str(detail.get("status") or "").upper()
        if service_status not in valid_service_states:
            raise ValueError(f"Stored collection status for '{service}' is missing or unsupported")
        detail["status"] = service_status
        if "errors" not in detail:
            detail["errors"] = []
        elif not isinstance(detail["errors"], list):
            raise ValueError(f"Stored collection errors for '{service}' have an invalid shape")

    # Legacy migrations stored their explanatory coverage note as a string list. Normalize
    # it at the API boundary so clients always receive {service, message} error objects.
    normalized_errors = []
    for item in result["collection_errors"]:
        if isinstance(item, str):
            normalized_errors.append({"service": "scan", "message": item})
        elif isinstance(item, dict):
            service = item.get("service")
            message = item.get("message")
            if not isinstance(service, str) or not service.strip():
                service = "scan"
            if not isinstance(message, str):
                message = json.dumps(item, sort_keys=True)
            normalized_errors.append({**item, "service": service, "message": message})
        else:
            normalized_errors.append({"service": "scan", "message": str(item)})
    result["collection_errors"] = normalized_errors
    return result


def get_scan_assessed_resource_ids(conn, scan_id):
    return {(row[0], row[1]) for row in conn.execute("SELECT resource_id,resource_type FROM scan_resources WHERE scan_id=?", (scan_id,)).fetchall()}


def get_last_scan_time(conn):
    row = conn.execute("SELECT COALESCE(completed_at,scanned_at) AS ts FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return row["ts"] + " UTC" if row and row["ts"] else None


def get_resources_scanned(conn) -> int:
    row = conn.execute("SELECT resources_assessed FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return row["resources_assessed"] if row else 0
