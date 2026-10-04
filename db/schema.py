"""
SQLite storage for the dashboard (stand-in for DynamoDB so the demo needs no AWS).
DB file: db/policyguard.db (override with POLICYGUARD_DB).
"""
import json
import os
import sqlite3

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
"""

AUDIT_FIELDS = ("id", "timestamp", "event_type", "details", "previous_hash", "entry_hash")


def connect(path: str = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def save_scan(conn, resources_scanned: int, classified: list, remediation: list, entries: list):
    """Replaces current violations with this scan; appends audit entries (log is append-only)."""
    by_key = {(r.get("rule"), r.get("resource_id")): r for r in remediation}
    with conn:
        conn.execute("INSERT INTO scans (resources_scanned) VALUES (?)", (resources_scanned,))
        conn.execute("DELETE FROM violations")
        conn.executemany(
            "INSERT INTO violations (rule, resource_id, clause, severity, remediation) VALUES (?,?,?,?,?)",
            [
                (v["rule"], v["resource_id"], v.get("clause"), v.get("severity"),
                 json.dumps(by_key.get((v["rule"], v["resource_id"]), {})))
                for v in classified
            ],
        )
        conn.executemany(
            "INSERT INTO audit_log (id, timestamp, event_type, details, previous_hash, entry_hash) VALUES (?,?,?,?,?,?)",
            [
                (e["id"], e["timestamp"], e["event_type"], json.dumps(e["details"]),
                 e["previous_hash"], e["entry_hash"])
                for e in entries
            ],
        )


def get_violations(conn) -> list:
    rows = conn.execute("SELECT * FROM violations ORDER BY id").fetchall()
    return [{**dict(r), "remediation": json.loads(r["remediation"] or "{}")} for r in rows]


def get_audit_log(conn) -> list:
    rows = conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
    return [
        {k: (json.loads(r[k]) if k == "details" else r[k]) for k in AUDIT_FIELDS}
        for r in rows
    ]


def get_last_scan_time(conn):
    row = conn.execute("SELECT scanned_at FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return row["scanned_at"] + " UTC" if row else None


def get_resources_scanned(conn) -> int:
    row = conn.execute("SELECT resources_scanned FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return row["resources_scanned"] if row else 0
