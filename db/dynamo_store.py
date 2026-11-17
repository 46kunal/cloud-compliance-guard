"""DynamoDB backend with the same function names and result shapes as db/schema.py (SQLite).

Tables (all PAY_PER_REQUEST, prefix from POLICYGUARD_TABLE_PREFIX, default "policyguard"):
  counters          pk name                          atomic id allocation
  scans             pk scan_id
  findings          pk finding_key, GSI id-index(id) one item per rule+resource+account
  finding_events    pk finding_id, sk event_id       lifecycle history
  finding_evidence  pk finding_id, sk scan_id        per-scan evidence snapshot + SHA-256
  scan_resources    pk scan_id, sk resource_key      resources successfully assessed per scan
  audit_log         pk chain, sk seq                 hash chain; conditional put keeps one linear history

Items carry a few indexed attributes plus nested documents, so different rules can store
differently shaped evidence without schema changes.
"""
import json
import os
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from db.schema import SERVICE_BY_TYPE, _now, _resource_type, normalize_scan, stable_finding_key

CHAIN = "main"


def _py(value):
    """Convert DynamoDB Decimals back to int/float, recursively."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: _py(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_py(v) for v in value]
    return value


def _ddb(value):
    """Convert a JSON-compatible value into something DynamoDB accepts (no floats, no empty strings)."""
    return json.loads(json.dumps(value), parse_float=Decimal)


class DynamoStore:
    """Connection-like handle. close() exists so callers can treat it like a SQLite connection."""

    def __init__(self, prefix=None, region=None, endpoint_url=None, create=False):
        self.prefix = prefix or os.environ.get("POLICYGUARD_TABLE_PREFIX", "policyguard")
        kwargs = {}
        region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if region:
            kwargs["region_name"] = region
        if endpoint_url or os.environ.get("POLICYGUARD_DYNAMODB_ENDPOINT"):
            kwargs["endpoint_url"] = endpoint_url or os.environ["POLICYGUARD_DYNAMODB_ENDPOINT"]
        self.resource = boto3.resource("dynamodb", **kwargs)
        self._tables = {}
        if create:
            ensure_tables(self)

    def table(self, name):
        if name not in self._tables:
            self._tables[name] = self.resource.Table(f"{self.prefix}-{name}")
        return self._tables[name]

    def close(self):
        pass


TABLE_DEFINITIONS = {
    "counters": {"keys": [("name", "S", "HASH")]},
    "scans": {"keys": [("scan_id", "N", "HASH")]},
    "findings": {"keys": [("finding_key", "S", "HASH")],
                 "gsi": [("id-index", "id", "N")]},
    "finding_events": {"keys": [("finding_id", "N", "HASH"), ("event_id", "N", "RANGE")]},
    "finding_evidence": {"keys": [("finding_id", "N", "HASH"), ("scan_id", "N", "RANGE")]},
    "scan_resources": {"keys": [("scan_id", "N", "HASH"), ("resource_key", "S", "RANGE")]},
    "audit_log": {"keys": [("chain", "S", "HASH"), ("seq", "N", "RANGE")]},
    "documents": {"keys": [("kind", "S", "HASH"), ("id", "S", "RANGE")]},
}


def ensure_tables(store):
    """Create missing tables (local dev and tests). In AWS the CloudFormation stack owns them."""
    client = store.resource.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    for name, definition in TABLE_DEFINITIONS.items():
        full = f"{store.prefix}-{name}"
        if full in existing:
            continue
        attrs = {k: t for k, t, _ in definition["keys"]}
        params = {
            "TableName": full, "BillingMode": "PAY_PER_REQUEST",
            "KeySchema": [{"AttributeName": k, "KeyType": r} for k, _, r in definition["keys"]],
        }
        gsis = []
        for index_name, attr, attr_type in definition.get("gsi", []):
            attrs[attr] = attr_type
            gsis.append({"IndexName": index_name, "KeySchema": [{"AttributeName": attr, "KeyType": "HASH"}],
                         "Projection": {"ProjectionType": "ALL"}})
        params["AttributeDefinitions"] = [{"AttributeName": k, "AttributeType": t} for k, t in attrs.items()]
        if gsis:
            params["GlobalSecondaryIndexes"] = gsis
        client.create_table(**params)
        client.get_waiter("table_exists").wait(TableName=full)


def connect(path=None):
    return DynamoStore()


def _next_id(store, name):
    response = store.table("counters").update_item(
        Key={"name": name}, UpdateExpression="ADD #v :one", ExpressionAttributeNames={"#v": "value"},
        ExpressionAttributeValues={":one": 1}, ReturnValues="UPDATED_NEW")
    return int(response["Attributes"]["value"])


def _scan_all(table, **kwargs):
    items = []
    while True:
        page = table.scan(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return [_py(i) for i in items]
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def _query_all(table, **kwargs):
    items = []
    while True:
        page = table.query(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return [_py(i) for i in items]
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def begin_scan(store, started_at=None, account_scope="configured AWS account", region_scope="configured region"):
    started_at = started_at or _now()
    scan_id = _next_id(store, "scan")
    store.table("scans").put_item(Item={
        "scan_id": scan_id, "scanned_at": started_at, "started_at": started_at, "status": "RUNNING",
        "account_scope": account_scope, "region_scope": region_scope, "resources_scanned": 0,
        "resources_discovered": 0, "resources_assessed": 0, "findings_detected": 0,
        "services_scanned": "[]", "service_statuses": "{}", "collection_errors": "[]"})
    return scan_id


def _all_findings(store):
    return _scan_all(store.table("findings"))


def save_scan(store, resources_scanned, classified, remediation, entries, *, scan_id=None, started_at=None,
              status="PARTIAL", account_scope="configured AWS account", region_scope="configured region",
              resources_assessed=None, services_scanned=None, service_statuses=None, collection_errors=None,
              allow_resolve=True, assessed_resource_records=None, evidence_records=None):
    now = _now()
    started_at = started_at or now
    if scan_id is None:
        scan_id = begin_scan(store, started_at, account_scope, region_scope)
    by_key = {(r.get("rule"), r.get("resource_id")): r for r in remediation}
    detected = {(v.get("rule"), v.get("resource_id")) for v in classified}
    service_statuses = service_statuses or {}

    store.table("scans").put_item(Item={
        "scan_id": scan_id, "scanned_at": now, "started_at": started_at, "completed_at": now, "status": status,
        "account_scope": account_scope, "region_scope": region_scope,
        "resources_scanned": resources_scanned, "resources_discovered": resources_scanned,
        "resources_assessed": resources_assessed if resources_assessed is not None else 0,
        "findings_detected": len(classified), "services_scanned": json.dumps(services_scanned or []),
        "service_statuses": json.dumps(service_statuses), "collection_errors": json.dumps(collection_errors or [])})

    with store.table("scan_resources").batch_writer(overwrite_by_pkeys=["scan_id", "resource_key"]) as batch:
        for r in assessed_resource_records or []:
            batch.put_item(Item={
                "scan_id": scan_id,
                "resource_key": stable_finding_key("resource", "aws", account_scope, r.get("resource_type"), r.get("resource_id")),
                "resource_id": r.get("resource_id", ""), "resource_type": r.get("resource_type", "unknown"),
                "service": SERVICE_BY_TYPE.get(r.get("resource_type"), "unknown")})

    findings = {f["finding_key"]: f for f in _all_findings(store)}
    findings_table, events_table = store.table("findings"), store.table("finding_events")

    def add_event(finding_id, event_type, from_status, to_status, details):
        events_table.put_item(Item={
            "finding_id": finding_id, "event_id": _next_id(store, "event"), "scan_id": scan_id,
            "event_type": event_type, "from_status": from_status, "to_status": to_status,
            "occurred_at": now, "details": json.dumps(details)})

    for violation in classified:
        rule, resource_id = violation["rule"], violation["resource_id"]
        provider = violation.get("provider", "aws")
        account = violation.get("account_scope", account_scope)
        resource_type = violation.get("resource_type", _resource_type(rule))
        key = stable_finding_key(rule, provider, account, resource_type, resource_id)
        remediation_json = json.dumps(by_key.get((rule, resource_id), {}))
        row = findings.get(key)
        if row is None:
            item = {"finding_key": key, "id": _next_id(store, "finding"), "rule": rule, "provider": provider,
                    "account_scope": account, "resource_type": resource_type, "resource_id": resource_id,
                    "clause": violation.get("clause"), "severity": violation.get("severity"), "status": "NEW",
                    "first_detected": now, "last_detected": now, "remediation": remediation_json}
            for optional in ("framework", "catalog_ids", "in_force"):
                if violation.get(optional) is not None:
                    item[optional] = _ddb(violation[optional])
            item = {k: v for k, v in item.items() if v is not None}
            findings_table.put_item(Item=item)
            findings[key] = item
            add_event(item["id"], "DETECTED", None, "NEW", violation)
            continue
        old_status = row["status"]
        service = SERVICE_BY_TYPE.get(resource_type)
        source_assessed = service_statuses.get(service, {}).get("status") == "SUCCESS"
        if old_status == "RESOLVED":
            new_status = "REOPENED"
        elif old_status == "NEW":
            new_status = "ACTIVE" if source_assessed else "NEW"
        elif old_status == "REOPENED":
            new_status = "ACTIVE" if source_assessed else "REOPENED"
        else:
            new_status = "ACTIVE"
        row.update({"status": new_status, "last_detected": now, "clause": violation.get("clause"),
                    "severity": violation.get("severity"), "remediation": remediation_json})
        row.pop("resolved_at", None)
        findings_table.put_item(Item={k: _ddb(v) if isinstance(v, (dict, list)) else v
                                      for k, v in row.items() if v is not None})
        if new_status != old_status:
            add_event(row["id"], "REOPENED" if new_status == "REOPENED" else "CONFIRMED", old_status, new_status, violation)

    if allow_resolve:
        for row in list(findings.values()):
            if row["status"] not in ("NEW", "ACTIVE", "REOPENED"):
                continue
            service = SERVICE_BY_TYPE.get(row["resource_type"])
            if (service and service_statuses.get(service, {}).get("status") == "SUCCESS"
                    and row["account_scope"] == account_scope
                    and (row["rule"], row["resource_id"]) not in detected):
                previous = row["status"]
                row.update({"status": "RESOLVED", "resolved_at": now})
                findings_table.put_item(Item={k: _ddb(v) if isinstance(v, (dict, list)) else v
                                              for k, v in row.items() if v is not None})
                add_event(row["id"], "RESOLVED", previous, "RESOLVED",
                          {"reason": "absent in successfully assessed service scope"})

    _append_audit_entries(store, entries)

    if evidence_records:
        from dashboard.evidence import canonical_evidence
        evidence_table = store.table("finding_evidence")
        for record in evidence_records:
            payload = record.get("evidence") or {}
            key = stable_finding_key(record.get("rule"), payload.get("provider", "aws"), account_scope,
                                     payload.get("resource_type", "unknown"), record.get("resource_id"))
            finding = findings.get(key)
            if not finding:
                continue
            evidence = dict(payload)
            evidence["finding_id"] = finding["id"]
            evidence["lifecycle_status"] = finding["status"]
            evidence["scan_status"] = status
            serialized, digest = canonical_evidence(evidence)
            try:
                evidence_table.put_item(
                    Item={"finding_id": finding["id"], "scan_id": scan_id, "evidence_json": serialized,
                          "evidence_sha256": digest, "evidence": _ddb(evidence)},
                    ConditionExpression="attribute_not_exists(finding_id)")
            except ClientError as error:
                if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
    return scan_id


def _append_audit_entries(store, entries):
    table = store.table("audit_log")
    last = _query_all(table, KeyConditionExpression=Key("chain").eq(CHAIN), ScanIndexForward=False, Limit=1)
    last = last[0] if last else None
    seq = last["seq"] if last else 0
    last_hash = last["entry_hash"] if last else None
    for entry in entries:
        if last_hash is not None and entry["previous_hash"] != last_hash:
            raise RuntimeError("Audit chain changed while scanning; the scan was not recorded. Retry.")
        seq += 1
        # Conditional put: a concurrent writer using the same sequence number fails instead of forking the chain.
        table.put_item(
            Item={"chain": CHAIN, "seq": seq, "id": entry["id"], "timestamp": entry["timestamp"],
                  "event_type": entry["event_type"], "details": json.dumps(entry["details"]),
                  "previous_hash": entry["previous_hash"], "entry_hash": entry["entry_hash"]},
            ConditionExpression="attribute_not_exists(seq)")
        last_hash = entry["entry_hash"]


def list_docs(store, kind):
    rows = _query_all(store.table("documents"), KeyConditionExpression=Key("kind").eq(kind))
    return [json.loads(r["data"]) for r in rows]


def get_doc(store, kind, doc_id):
    item = store.table("documents").get_item(Key={"kind": kind, "id": str(doc_id)}).get("Item")
    return json.loads(item["data"]) if item else None


def put_doc(store, kind, doc_id, data):
    store.table("documents").put_item(Item={"kind": kind, "id": str(doc_id), "data": json.dumps(data, sort_keys=True),
                                            "updated_at": _now()})


def delete_doc(store, kind, doc_id):
    store.table("documents").delete_item(Key={"kind": kind, "id": str(doc_id)})


def append_audit_events(store, events):
    """Append (event_type, details) pairs to the chain; retried if another writer extends it first."""
    from lambdas.audit_logger.hash_chain import GENESIS, append_entry
    for attempt in range(4):
        chain = get_audit_log(store)
        previous = chain[-1]["entry_hash"] if chain else GENESIS
        entries = []
        for event_type, details in events:
            entry = append_entry(event_type, details, previous)
            entries.append(entry)
            previous = entry["entry_hash"]
        try:
            _append_audit_entries(store, entries)
            return entries
        except (RuntimeError, ClientError):
            if attempt == 3:
                raise
    return []


def get_violations(store):
    rows = sorted((f for f in _all_findings(store) if f["status"] != "RESOLVED"), key=lambda f: f["id"])
    return [{**r, "remediation": json.loads(r.get("remediation") or "{}"), "detected_at": r["first_detected"]} for r in rows]


def get_findings(store, include_resolved=True):
    rows = _all_findings(store)
    if not include_resolved:
        rows = [r for r in rows if r["status"] != "RESOLVED"]
    with_evidence = {e["finding_id"] for e in _scan_all(store.table("finding_evidence"),
                                                        ProjectionExpression="finding_id")}
    rows.sort(key=lambda r: r["id"], reverse=True)
    return [{**r, "evidence_available": r["id"] in with_evidence,
             "remediation": json.loads(r.get("remediation") or "{}")} for r in rows]


def get_finding(store, finding_id):
    page = store.table("findings").query(IndexName="id-index", KeyConditionExpression=Key("id").eq(int(finding_id)))
    items = page.get("Items", [])
    if not items:
        return None
    row = _py(items[0])
    return {**row, "remediation": json.loads(row.get("remediation") or "{}")}


def get_finding_events(store, finding_id=None):
    table = store.table("finding_events")
    if finding_id is None:
        rows = sorted(_scan_all(table), key=lambda r: r["event_id"], reverse=True)
    else:
        rows = _query_all(table, KeyConditionExpression=Key("finding_id").eq(int(finding_id)))
    return [{**r, "id": r["event_id"], "details": json.loads(r.get("details") or "{}")} for r in rows]


def count_finding_events(store, scan_id, event_type):
    return sum(1 for r in _scan_all(store.table("finding_events"))
               if r.get("scan_id") == scan_id and r.get("event_type") == event_type)


def get_finding_evidence(store, finding_id):
    rows = _query_all(store.table("finding_evidence"), KeyConditionExpression=Key("finding_id").eq(int(finding_id)))
    result = []
    for row in rows:
        scan = store.table("scans").get_item(Key={"scan_id": row["scan_id"]}).get("Item")
        scan = _py(scan) if scan else {}
        item = json.loads(row["evidence_json"])
        item.update({"evidence_id": f"{row['finding_id']}-{row['scan_id']}", "finding_id": row["finding_id"],
                     "scan_id": row["scan_id"], "scan_status": scan.get("status"),
                     "account_scope": item.get("account_scope") or scan.get("account_scope"),
                     "region_scope": item.get("region_scope") or scan.get("region_scope"),
                     "evidence_sha256": row["evidence_sha256"]})
        result.append(item)
    return result


def get_audit_log(store):
    rows = _query_all(store.table("audit_log"), KeyConditionExpression=Key("chain").eq(CHAIN))
    return [{"id": r["id"], "timestamp": r["timestamp"], "event_type": r["event_type"],
             "details": json.loads(r["details"]), "previous_hash": r["previous_hash"],
             "entry_hash": r["entry_hash"]} for r in rows]


def _scan_item(store, item):
    item = dict(_py(item))
    item["id"] = item.pop("scan_id")
    return item


def get_scans(store, limit=30):
    rows = sorted(_scan_all(store.table("scans")), key=lambda r: r["scan_id"], reverse=True)[:limit]
    return [normalize_scan(_scan_item(store, r)) for r in rows]


def get_latest_scan(store):
    rows = _scan_all(store.table("scans"))
    if not rows:
        return None
    latest = max(rows, key=lambda r: r["scan_id"])
    return normalize_scan(_scan_item(store, latest))


def get_scan_assessed_resource_ids(store, scan_id):
    rows = _query_all(store.table("scan_resources"), KeyConditionExpression=Key("scan_id").eq(int(scan_id)))
    return {(r["resource_id"], r["resource_type"]) for r in rows}


def get_last_scan_time(store):
    latest = get_latest_scan(store)
    if not latest:
        return None
    stamp = latest.get("completed_at") or latest.get("scanned_at")
    return stamp + " UTC" if stamp else None


def get_resources_scanned(store):
    latest = get_latest_scan(store)
    return latest["resources_assessed"] if latest else 0
