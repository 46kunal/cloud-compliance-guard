"""Controls register and incident clock API. Auditors can read; admins record and change."""
from flask import Blueprint, jsonify, request

from dashboard import process
from dashboard.auth import current_user
from db.store import connect, get_doc

process_bp = Blueprint("process", __name__)


def _actor():
    return (current_user() or {}).get("username", "unknown")


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _run(fn, status=200):
    conn = connect()
    try:
        return jsonify(fn(conn)), status
    except process.ProcessError as error:
        return jsonify({"error": str(error)}), 400
    finally:
        conn.close()


# ---- controls ----
@process_bp.route("/api/controls")
def controls():
    return _run(lambda conn: {"controls": process.list_controls(conn)})


@process_bp.route("/api/controls/<control_id>/attest", methods=["POST"])
def attest(control_id):
    data = _body()

    def run(conn):
        process.attest(conn, control_id, data.get("owner"), data.get("evidence_note"), data.get("evidence_url"),
                       data.get("review_days"), _actor())
        return {"controls": process.list_controls(conn)}
    return _run(run)


@process_bp.route("/api/controls/<control_id>/revoke", methods=["POST"])
def revoke(control_id):
    def run(conn):
        process.revoke(conn, control_id, _actor())
        return {"controls": process.list_controls(conn)}
    return _run(run)


# ---- incidents ----
@process_bp.route("/api/incidents")
def incidents():
    return _run(lambda conn: {"incidents": process.list_incidents(conn), "types": process.annexure_types()})


@process_bp.route("/api/incidents", methods=["POST"])
def open_incident():
    data = _body()

    def run(conn):
        process.open_incident(conn, data, _actor())
        return {"incidents": process.list_incidents(conn), "types": process.annexure_types()}
    return _run(run, 201)


@process_bp.route("/api/incidents/<incident_id>/step", methods=["POST"])
def step(incident_id):
    data = _body()

    def run(conn):
        process.record_milestone(conn, incident_id, data.get("step"), _actor(), data.get("at"))
        return {"incidents": process.list_incidents(conn), "types": process.annexure_types()}
    return _run(run)


@process_bp.route("/api/incidents/<incident_id>/drafts")
def incident_drafts(incident_id):
    def run(conn):
        incident = get_doc(conn, process.INCIDENTS_KIND, incident_id)
        if not incident:
            raise process.ProcessError("Unknown incident.")
        return process.drafts(incident)
    return _run(run)
