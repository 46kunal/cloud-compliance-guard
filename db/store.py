"""Storage facade. Application code imports from here and never knows which database it uses.

Backend selection:
  POLICYGUARD_BACKEND=sqlite    (default) local file, used for development and most tests
  POLICYGUARD_BACKEND=dynamodb  DynamoDB tables, used when deployed on AWS

Every function dispatches on the connection object it is given, so a SQLite connection always
uses the SQLite implementation even if the environment says DynamoDB.
"""
import os

from db import schema as _sqlite
from db import dynamo_store as _dynamo


def backend_name() -> str:
    return os.environ.get("POLICYGUARD_BACKEND", "sqlite").lower()


def connect(path: str = None):
    if backend_name() == "dynamodb":
        return _dynamo.connect()
    return _sqlite.connect(path) if path else _sqlite.connect()


def _impl(conn):
    return _dynamo if isinstance(conn, _dynamo.DynamoStore) else _sqlite


def _delegate(name):
    def call(conn, *args, **kwargs):
        return getattr(_impl(conn), name)(conn, *args, **kwargs)
    call.__name__ = name
    return call


begin_scan = _delegate("begin_scan")
save_scan = _delegate("save_scan")
get_violations = _delegate("get_violations")
get_findings = _delegate("get_findings")
get_finding = _delegate("get_finding")
get_finding_events = _delegate("get_finding_events")
count_finding_events = _delegate("count_finding_events")
get_finding_evidence = _delegate("get_finding_evidence")
get_audit_log = _delegate("get_audit_log")
get_scans = _delegate("get_scans")
get_latest_scan = _delegate("get_latest_scan")
get_scan_assessed_resource_ids = _delegate("get_scan_assessed_resource_ids")
get_last_scan_time = _delegate("get_last_scan_time")
get_resources_scanned = _delegate("get_resources_scanned")
list_docs = _delegate("list_docs")
get_doc = _delegate("get_doc")
put_doc = _delegate("put_doc")
delete_doc = _delegate("delete_doc")
append_audit_events = _delegate("append_audit_events")
