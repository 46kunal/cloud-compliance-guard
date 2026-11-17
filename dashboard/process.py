"""Obligations that are about process, not cloud settings: the controls register and the incident clock.

Controls: an admin records the owner, the evidence and the review date for each manual duty. PolicyGuard tracks
those facts and shows when a review is overdue. It does not decide whether the evidence is good enough.

Incidents: opening an incident starts the clocks the rules set: CERT-In within 6 hours (Direction (ii)), and for
personal data breaches the Data Protection Board without delay with a detailed report within 72 hours, and
affected people without delay (DPDP Rule 7, from a third-party reproduction of the rule text). The module drafts
the report text for a person to review and file. It never sends anything to a regulator.
"""
import json
import os
import re
from datetime import datetime, timedelta, timezone

from compliance.incident_types import ANNEXURE_I, CERTIN_CONTACT, TYPE_IDS, TYPE_TEXT

CONTROLS_KIND = "controls"
INCIDENTS_KIND = "incidents"
CERTIN_HOURS = 6
BOARD_DETAIL_HOURS = 72
MILESTONES = {"certin_reported": "certin_reported_at", "board_notified": "board_notified_at",
              "board_detail_sent": "board_detail_sent_at", "individuals_notified": "individuals_notified_at",
              "closed": "closed_at"}
PERSONAL_DATA_ONLY = {"board_notified", "board_detail_sent", "individuals_notified"}

CONTROLS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "compliance", "controls.json")


class ProcessError(Exception):
    """A problem with a request; the message is safe to show."""


def _now():
    return datetime.now(timezone.utc)


def _parse(value, default=None):
    if not value:
        return default
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise ProcessError("A date or time looks wrong. Use a format like 2026-11-17T09:30:00+05:30.")
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _audit(conn, event, actor, **details):
    from db.store import append_audit_events
    append_audit_events(conn, [(event, {"actor": actor, **details})])


# ------------------------------------------------------------------ controls
def control_definitions() -> list:
    with open(os.path.abspath(CONTROLS_PATH), encoding="utf-8") as handle:
        return json.load(handle)["controls"]


def control_state(doc, now=None) -> str:
    if not doc or doc.get("status") != "ATTESTED":
        return "NOT_ATTESTED"
    due = _parse(doc.get("review_due"))
    return "OVERDUE" if due and due < (now or _now()) else "ATTESTED"


def list_controls(conn, now=None) -> list:
    from db.store import list_docs
    docs = {d["control_id"]: d for d in list_docs(conn, CONTROLS_KIND)}
    result = []
    for definition in control_definitions():
        doc = docs.get(definition["id"])
        result.append({**definition, "state": control_state(doc, now),
                       "owner": (doc or {}).get("owner"), "evidence_url": (doc or {}).get("evidence_url"),
                       "evidence_note": (doc or {}).get("evidence_note"), "attested_by": (doc or {}).get("attested_by"),
                       "attested_at": (doc or {}).get("attested_at"), "review_due": (doc or {}).get("review_due")})
    return result


def controls_by_obligation(conn, now=None) -> dict:
    summary = {}
    for control in list_controls(conn, now):
        entry = summary.setdefault(control["obligation_id"], {"total": 0, "attested": 0, "overdue": 0})
        entry["total"] += 1
        entry["attested"] += control["state"] == "ATTESTED"
        entry["overdue"] += control["state"] == "OVERDUE"
    return summary


def attest(conn, control_id, owner, evidence_note, evidence_url, review_days, actor):
    from db.store import put_doc
    if control_id not in {d["id"] for d in control_definitions()}:
        raise ProcessError("Unknown control.")
    owner, note, url = (owner or "").strip(), (evidence_note or "").strip(), (evidence_url or "").strip()
    if not owner or len(owner) > 80:
        raise ProcessError("Name the person or team that owns this control (up to 80 characters).")
    if len(note) < 15 or len(note) > 1000:
        raise ProcessError("Describe the evidence in 15 to 1000 characters, so a reviewer can find it.")
    if url and not re.match(r"^https://[^\s]{4,500}$", url):
        raise ProcessError("The evidence link must start with https://.")
    try:
        days = int(review_days or 180)
    except (TypeError, ValueError):
        raise ProcessError("Review period must be a number of days.")
    if not 30 <= days <= 400:
        raise ProcessError("Review period must be between 30 and 400 days.")
    now = _now()
    put_doc(conn, CONTROLS_KIND, control_id, {
        "control_id": control_id, "status": "ATTESTED", "owner": owner, "evidence_note": note, "evidence_url": url or None,
        "attested_by": actor, "attested_at": now.isoformat(), "review_due": (now + timedelta(days=days)).isoformat()})
    _audit(conn, "CONTROL_ATTESTED", actor, control_id=control_id, owner=owner, review_days=days)


def revoke(conn, control_id, actor):
    from db.store import delete_doc
    if control_id not in {d["id"] for d in control_definitions()}:
        raise ProcessError("Unknown control.")
    delete_doc(conn, CONTROLS_KIND, control_id)
    _audit(conn, "CONTROL_REVOKED", actor, control_id=control_id)


# ------------------------------------------------------------------ incidents
def _next_id(conn) -> str:
    from db.store import list_docs
    numbers = [int(d["incident_id"].split("-")[1]) for d in list_docs(conn, INCIDENTS_KIND) if d.get("incident_id", "").startswith("INC-")]
    return f"INC-{(max(numbers) + 1 if numbers else 1):04d}"


def open_incident(conn, data: dict, actor: str, now=None) -> dict:
    from db.store import put_doc
    now = now or _now()
    title = (data.get("title") or "").strip()
    if not 3 <= len(title) <= 120:
        raise ProcessError("Give the incident a title of 3 to 120 characters.")
    type_id = str(data.get("incident_type") or "")
    if type_id not in TYPE_IDS:
        raise ProcessError("Choose an incident type from CERT-In Annexure I.")
    description = (data.get("description") or "").strip()
    if len(description) > 2000:
        raise ProcessError("Keep the description under 2000 characters.")
    detected = _parse(data.get("detected_at"), now)
    if detected > now + timedelta(minutes=5):
        raise ProcessError("The detection time cannot be in the future.")
    incident = {"incident_id": _next_id(conn), "title": title, "incident_type": type_id, "description": description,
                "personal_data_involved": bool(data.get("personal_data_involved")),
                "related_finding_id": data.get("related_finding_id"), "detected_at": detected.isoformat(),
                "opened_by": actor, "opened_at": now.isoformat(), "status": "OPEN"}
    put_doc(conn, INCIDENTS_KIND, incident["incident_id"], incident)
    _audit(conn, "INCIDENT_OPENED", actor, incident_id=incident["incident_id"], incident_type=type_id,
           personal_data_involved=incident["personal_data_involved"], detected_at=incident["detected_at"])
    return incident


def record_milestone(conn, incident_id, milestone, actor, at=None, now=None) -> dict:
    from db.store import get_doc, put_doc
    now = now or _now()
    incident = get_doc(conn, INCIDENTS_KIND, incident_id)
    if not incident:
        raise ProcessError("Unknown incident.")
    if milestone not in MILESTONES:
        raise ProcessError("Unknown step.")
    if milestone in PERSONAL_DATA_ONLY and not incident.get("personal_data_involved"):
        raise ProcessError("This incident is not marked as involving personal data, so the DPDP notices do not apply.")
    when = _parse(at, now)
    if when > now + timedelta(minutes=5):
        raise ProcessError("The time cannot be in the future.")
    if when < _parse(incident["detected_at"]):
        raise ProcessError("The time cannot be before the incident was detected.")
    field = MILESTONES[milestone]
    if incident.get(field):
        raise ProcessError("That step is already recorded.")
    incident[field] = when.isoformat()
    if milestone == "closed":
        incident["status"] = "CLOSED"
    put_doc(conn, INCIDENTS_KIND, incident_id, incident)
    _audit(conn, "INCIDENT_STEP", actor, incident_id=incident_id, step=milestone, at=when.isoformat())
    return incident


def deadlines(incident: dict, now=None) -> list:
    """Each clock for an incident: what is due, when, and whether it was met."""
    now = now or _now()
    detected = _parse(incident["detected_at"])
    items = [("certin", "Report to CERT-In", "Within 6 hours of noticing the incident (Direction (ii))",
              detected + timedelta(hours=CERTIN_HOURS), incident.get("certin_reported_at"))]
    if incident.get("personal_data_involved"):
        items += [
            ("board_first", "Inform the Data Protection Board", "Without delay (DPDP Rule 7)", None, incident.get("board_notified_at")),
            ("individuals", "Inform affected people", "Without delay (DPDP Rule 7)", None, incident.get("individuals_notified_at")),
            ("board_detail", "Detailed report to the Board", "Within 72 hours, longer only if the Board allows on written request (DPDP Rule 7)",
             detected + timedelta(hours=BOARD_DETAIL_HOURS), incident.get("board_detail_sent_at"))]
    result = []
    for key, label, rule, due, done in items:
        done_at = _parse(done) if done else None
        if done_at:
            state = "DONE_LATE" if due and done_at > due else "DONE"
        elif due and now > due:
            state = "OVERDUE"
        else:
            state = "PENDING"
        result.append({"key": key, "label": label, "rule": rule, "due_at": due.isoformat() if due else None,
                       "done_at": done_at.isoformat() if done_at else None, "state": state,
                       "seconds_left": int((due - now).total_seconds()) if due and not done_at else None})
    return result


def list_incidents(conn, now=None) -> list:
    from db.store import list_docs
    incidents = sorted(list_docs(conn, INCIDENTS_KIND), key=lambda i: i["detected_at"], reverse=True)
    return [{**i, "type_text": TYPE_TEXT.get(i["incident_type"], i["incident_type"]), "deadlines": deadlines(i, now)}
            for i in incidents]


def drafts(incident: dict) -> dict:
    """Starting text for a person to review and complete. Nothing here is sent anywhere."""
    kind = TYPE_TEXT.get(incident["incident_type"], incident["incident_type"])
    base = (f"Incident {incident['incident_id']}: {incident['title']}\n"
            f"Type (CERT-In Annexure I, item {incident['incident_type']}): {kind}\n"
            f"Detected: {incident['detected_at']}\n"
            f"Description: {incident.get('description') or '[describe what happened]'}\n")
    certin = (f"To: {CERTIN_CONTACT['email']}  (phone {CERTIN_CONTACT['phone']}, fax {CERTIN_CONTACT['fax']})\n"
              f"Subject: Cyber incident report - {incident['title']}\n\n{base}"
              "Organisation and point of contact: [name, email, phone]\n"
              "Date and time the incident occurred (if different from detection): [fill in]\n"
              "Systems, accounts and data affected: [fill in, for example AWS account IDs, services, resources]\n"
              "Personal data involved: " + ("yes" if incident.get("personal_data_involved") else "no") + "\n"
              "Actions taken so far: [fill in]\n"
              "Note: CERT-In also publishes its own reporting form at " + CERTIN_CONTACT["website"] + ". Use it if it asks for more.")
    result = {"certin": certin}
    if incident.get("personal_data_involved"):
        result["board_first"] = ("To: Data Protection Board of India\nSubject: Personal data breach intimation\n\n" + base +
                                 "Nature, extent, timing and location of the breach: [fill in]\n"
                                 "Likely impact: [fill in]\n")
        result["board_detail"] = ("To: Data Protection Board of India\nSubject: Personal data breach - detailed information\n\n" + base +
                                  "Updated detail of the breach: [fill in]\n"
                                  "Broad facts on the events, circumstances and reasons: [fill in]\n"
                                  "Measures implemented or proposed to mitigate risk: [fill in]\n"
                                  "Findings about the person who caused the breach, if any: [fill in]\n"
                                  "Remedial measures to prevent recurrence: [fill in]\n"
                                  "Report on the intimations given to affected people: [fill in]\n")
        result["individuals"] = ("Subject: Notice about a personal data breach\n\n"
                                 "What happened, and when (nature, extent and timing): [fill in plain language]\n"
                                 "What this could mean for you: [fill in]\n"
                                 "What we are doing to reduce the risk: [fill in]\n"
                                 "What you can do to protect yourself: [fill in]\n"
                                 "Who to contact with questions (business contact): [name, email, phone]\n")
    result["disclaimer"] = ("These are drafts for a person to review, complete and file. PolicyGuard never sends anything to a regulator. "
                            "The DPDP notice contents come from a third-party reproduction of Rule 7 and are not yet confirmed against the gazette.")
    return result


def annexure_types() -> list:
    return [{"id": item_id, "text": text} for item_id, text in ANNEXURE_I]
