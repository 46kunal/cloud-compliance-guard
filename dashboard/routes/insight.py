"""Read-only insight endpoints: frameworks, scan history, infrastructure/usage and exports."""
import csv
import io
import json
import os
from datetime import datetime

from flask import Blueprint, Response, jsonify, render_template

from compliance.catalog import framework_summary, load_catalog, obligations_for_rule
from dashboard.account import in_scope, latest_scan_in_scope, visible_scope
from dashboard.instance import instance_info
from db.store import (backend_name, connect, get_finding_evidence, get_findings, get_latest_scan, get_scans,
                      get_violations)

insight_bp = Blueprint("insight", __name__)

DISCLAIMER = ("This tool checks cloud configuration against specific controls. A passing result is not a legal "
              "compliance determination. Obligations marked not assessed need review by a person.")

# Illustrative list prices for the cost comparison. They are assumptions, not billing data;
# verify against the AWS Pricing Calculator for your region before quoting them.
PRICING = {"lambda_per_gb_second": 0.0000166667, "lambda_per_million_requests": 0.20,
           "ec2_t3_micro_hourly": 0.0104, "scanner_memory_gb": 0.5}


def _duration_seconds(scan):
    try:
        start, end = datetime.fromisoformat(scan["started_at"]), datetime.fromisoformat(scan["completed_at"])
        return max(0.0, (end - start).total_seconds())
    except (TypeError, ValueError, KeyError):
        return None


def _with_store(fn):
    conn = connect()
    try:
        return fn(conn)
    finally:
        conn.close()


def _control_status():
    try:
        from dashboard.process import controls_by_obligation
        return _with_store(controls_by_obligation)
    except Exception:
        return {}


@insight_bp.route("/api/frameworks")
def frameworks():
    open_findings = _with_store(lambda conn: in_scope(get_violations(conn), visible_scope(conn)))
    catalog = load_catalog()
    return jsonify({
        "catalog_version": catalog["catalog_version"], "last_reviewed": catalog["last_reviewed"],
        "profile": os.environ.get("POLICYGUARD_PROFILE", "baseline"), "disclaimer": DISCLAIMER,
        "items": framework_summary(open_findings, _control_status()),
    })


@insight_bp.route("/api/scans")
def scans():
    rows = _with_store(lambda conn: in_scope(get_scans(conn, 60), visible_scope(conn)))
    return jsonify([{
        "id": s["id"], "status": s["status"], "started_at": s.get("started_at"), "completed_at": s.get("completed_at"),
        "duration_seconds": _duration_seconds(s), "resources_discovered": s.get("resources_discovered"),
        "resources_assessed": s.get("resources_assessed"), "findings_detected": s.get("findings_detected"),
        "account_scope": s.get("account_scope"), "region_scope": s.get("region_scope"),
        "services_scanned": s.get("services_scanned"), "collection_errors": s.get("collection_errors"),
    } for s in rows])


@insight_bp.route("/api/instance")
def instance():
    return jsonify({**instance_info(), "storage_backend": backend_name(),
                    "profile": os.environ.get("POLICYGUARD_PROFILE", "baseline"),
                    "auth_mode": os.environ.get("POLICYGUARD_AUTH", "off")})


def _autoscaling_summary():
    name = os.environ.get("POLICYGUARD_ASG_NAME")
    if not name:
        return None
    try:
        import boto3
        client = boto3.client("autoscaling", region_name=instance_info().get("region"))
        group = client.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
        activities = client.describe_scaling_activities(AutoScalingGroupName=name, MaxRecords=8)["Activities"]
        return {
            "name": name, "min": group["MinSize"], "max": group["MaxSize"], "desired": group["DesiredCapacity"],
            "instances": [{"id": i["InstanceId"], "zone": i["AvailabilityZone"], "state": i["LifecycleState"],
                           "health": i["HealthStatus"]} for i in group["Instances"]],
            "recent_activities": [{"description": a.get("Description"), "cause": (a.get("Cause") or "")[:160],
                                   "status": a.get("StatusCode"), "started": a["StartTime"].isoformat()}
                                  for a in activities],
        }
    except Exception as error:
        return {"name": name, "error": f"Could not read the Auto Scaling group: {error}"}


def _cost_model(scans_list):
    interval = int(os.environ.get("POLICYGUARD_SCAN_INTERVAL_MINUTES", "15"))
    # Legacy scans were recorded before timings existed (start == end), so they would drag the average to ~0 s.
    durations = [d for d in (_duration_seconds(s) for s in scans_list) if d is not None and d > 0]
    avg = sum(durations) / len(durations) if durations else None
    runs_per_month = int(30 * 24 * 60 / interval)
    if avg is None:
        return {"available": False, "reason": "No completed scans yet."}
    gb_seconds = runs_per_month * avg * PRICING["scanner_memory_gb"]
    serverless = gb_seconds * PRICING["lambda_per_gb_second"] + runs_per_month / 1e6 * PRICING["lambda_per_million_requests"]
    always_on = 30 * 24 * PRICING["ec2_t3_micro_hourly"]
    return {
        "available": True, "label": "Estimate from assumed list prices, not billing data",
        "scan_interval_minutes": interval, "runs_per_month": runs_per_month, "avg_scan_seconds": round(avg, 2),
        "serverless_scanner_usd_per_month": round(serverless, 4),
        "always_on_instance_usd_per_month": round(always_on, 2),
        "saving_percent": round(100 * (1 - serverless / always_on), 1) if always_on else None,
        "assumptions": PRICING,
    }


@insight_bp.route("/api/usage")
def usage():
    scans_list = _with_store(lambda conn: in_scope(get_scans(conn, 500), visible_scope(conn)))
    completed = [s for s in scans_list if s["status"] in ("COMPLETED", "PARTIAL") and s.get("account_scope") != "legacy"]
    return jsonify({
        "scans_recorded": len(scans_list), "scans_completed": len(completed),
        "instance": instance_info(), "storage_backend": backend_name(),
        "autoscaling": _autoscaling_summary(), "cost": _cost_model(completed),
    })


def _csv_safe(value):
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@insight_bp.route("/api/export/findings.csv")
def export_csv():
    rows = _with_store(lambda conn: in_scope(get_findings(conn), visible_scope(conn)))
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "status", "severity", "rule", "resource_type", "resource_id", "account_scope",
                     "first_detected", "last_detected", "resolved_at", "clause", "obligations"])
    for f in rows:
        writer.writerow([_csv_safe(v) for v in (
            f["id"], f["status"], f.get("severity"), f["rule"], f.get("resource_type"), f["resource_id"],
            f.get("account_scope"), f.get("first_detected"), f.get("last_detected"), f.get("resolved_at"),
            f.get("clause"), "; ".join(o["id"] for o in obligations_for_rule(f["rule"])))])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=policyguard-findings.csv"})


def _bundle(conn):
    scope = visible_scope(conn)
    scan = latest_scan_in_scope(conn, scope)
    findings = in_scope(get_findings(conn), scope)
    for f in findings:
        f["obligations"] = obligations_for_rule(f["rule"])
        f["evidence"] = get_finding_evidence(conn, f["id"]) if f["evidence_available"] else []
    return scan, findings


def _evidence_dir():
    """Shared folder (an EFS mount on AWS) where every server saves the bundles it generates."""
    path = os.environ.get("POLICYGUARD_EVIDENCE_DIR")
    return path if path and os.path.isdir(path) else None


@insight_bp.route("/api/export/evidence-bundle.json")
def export_bundle():
    scan, findings = _with_store(_bundle)
    catalog = load_catalog()
    now = datetime.utcnow()
    bundle = {"generated_at": now.isoformat() + "Z", "tool": "PolicyGuard", "generated_by_instance": instance_info()["instance_id"],
              "catalog_version": catalog["catalog_version"], "profile": os.environ.get("POLICYGUARD_PROFILE", "baseline"),
              "disclaimer": DISCLAIMER, "latest_scan": scan, "findings": findings}
    body = json.dumps(bundle, indent=2, default=str)
    folder = _evidence_dir()
    if folder:
        try:
            name = "evidence-bundle-scan%s-%s.json" % (scan["id"] if scan else 0, now.strftime("%Y%m%dT%H%M%SZ"))
            with open(os.path.join(folder, name), "w", encoding="utf-8") as handle:
                handle.write(body)
        except OSError:
            pass  # saving a copy is a convenience; the download must still work
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=policyguard-evidence-bundle.json"})


@insight_bp.route("/api/reports/saved")
def saved_reports():
    folder = _evidence_dir()
    if not folder:
        return jsonify({"enabled": False, "files": []})
    files = []
    for name in sorted(os.listdir(folder), reverse=True)[:50]:
        path = os.path.join(folder, name)
        if name.endswith(".json") and os.path.isfile(path):
            files.append({"name": name, "bytes": os.path.getsize(path),
                          "modified": datetime.utcfromtimestamp(os.path.getmtime(path)).isoformat() + "Z"})
    return jsonify({"enabled": True, "folder": folder, "files": files})


@insight_bp.route("/reports/print")
def printable_report():
    scan, findings = _with_store(_bundle)
    open_findings = [f for f in findings if f["status"] != "RESOLVED"]
    catalog = load_catalog()
    return render_template("report_print.html", scan=scan, findings=findings, open_findings=open_findings,
                           summary=framework_summary(open_findings, _control_status()), catalog=catalog, disclaimer=DISCLAIMER,
                           profile=os.environ.get("POLICYGUARD_PROFILE", "baseline"),
                           generated=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
