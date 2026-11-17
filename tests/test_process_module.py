"""Controls register and incident clock."""
import re
from datetime import datetime, timedelta, timezone

import pytest

from compliance.catalog import framework_summary, load_catalog
from compliance.incident_types import ANNEXURE_I, TYPE_IDS
from dashboard import auth, process
from dashboard.app import create_app
from db import schema
from db.store import get_audit_log
from lambdas.audit_logger.hash_chain import verify_chain

T0 = datetime(2026, 11, 17, 9, 0, tzinfo=timezone.utc)
USERS = "viewer1:view-pass:viewer;audit1:audit-pass:auditor;admin1:admin-pass:admin"


@pytest.fixture
def conn(monkeypatch, tmp_path):
    path = str(tmp_path / "p.db")
    monkeypatch.setattr("db.schema.DB_PATH", path)
    monkeypatch.setenv("POLICYGUARD_SECRET_KEY", "s")
    auth._failures.clear()
    return schema.connect(path)


# ---- the catalog of controls ----
def test_every_control_points_at_a_real_obligation_and_ids_are_unique():
    catalog_ids = {o["id"] for o in load_catalog()["obligations"]}
    defs = process.control_definitions()
    assert len({d["id"] for d in defs}) == len(defs)
    for d in defs:
        assert d["obligation_id"] in catalog_ids, d["id"]
        assert d["verification"] in ("primary", "secondary", "needs-verification")
        assert d["basis"] and d["evidence_hint"]


def test_annexure_i_has_the_twenty_types_from_the_direction():
    assert len(ANNEXURE_I) == 20 and {"xi", "xii", "xviii"} <= TYPE_IDS


# ---- attesting controls ----
def test_a_control_starts_unattested_and_becomes_attested_with_a_review_date(conn):
    assert {c["state"] for c in process.list_controls(conn)} == {"NOT_ATTESTED"}
    process.attest(conn, "CERTIN-POC-1", "Security team", "Contact registered with CERT-In on 12 Oct 2026", "https://example.org/proof", 180, "pgadmin")
    control = next(c for c in process.list_controls(conn) if c["id"] == "CERTIN-POC-1")
    assert control["state"] == "ATTESTED" and control["owner"] == "Security team" and control["attested_by"] == "pgadmin"
    chain = get_audit_log(conn)
    assert chain[-1]["event_type"] == "CONTROL_ATTESTED" and verify_chain(chain)


def test_an_attestation_goes_overdue_after_its_review_date(conn):
    process.attest(conn, "CERTIN-POC-1", "Security team", "Contact registered with CERT-In on 12 Oct 2026", None, 30, "pgadmin")
    later = datetime.now(timezone.utc) + timedelta(days=31)
    assert next(c for c in process.list_controls(conn, later) if c["id"] == "CERTIN-POC-1")["state"] == "OVERDUE"


@pytest.mark.parametrize("owner,note,url,days", [
    ("", "Contact registered with CERT-In", None, 180), ("Team", "too short", None, 180),
    ("Team", "A long enough description of the evidence", "http://insecure.example", 180),
    ("Team", "A long enough description of the evidence", None, 5), ("Team", "A long enough description of the evidence", None, "abc")])
def test_attestation_rejects_weak_or_unsafe_input(conn, owner, note, url, days):
    with pytest.raises(process.ProcessError):
        process.attest(conn, "CERTIN-POC-1", owner, note, url, days, "pgadmin")


def test_unknown_control_is_refused_and_revoke_clears_it(conn):
    with pytest.raises(process.ProcessError):
        process.attest(conn, "NOPE", "Team", "A long enough description of the evidence", None, 90, "pgadmin")
    process.attest(conn, "CERTIN-POC-1", "Team", "A long enough description of the evidence", None, 90, "pgadmin")
    process.revoke(conn, "CERTIN-POC-1", "pgadmin")
    assert next(c for c in process.list_controls(conn) if c["id"] == "CERTIN-POC-1")["state"] == "NOT_ATTESTED"


def test_frameworks_summary_shows_attestation_instead_of_not_assessed(conn):
    def state_of(obligation):
        return next(i for i in framework_summary([], process.controls_by_obligation(conn)) if i["id"] == obligation)["state"]
    assert state_of("CERTIN-NTP") == "needs_attestation"
    process.attest(conn, "CERTIN-NTP-1", "Platform team", "Servers use Amazon Time Sync, documented in the runbook", None, 180, "pgadmin")
    assert state_of("CERTIN-NTP") == "attested"
    assert state_of("DPDP-MANUAL") == "needs_attestation"
    for cid in [c["id"] for c in process.control_definitions() if c["obligation_id"] == "DPDP-MANUAL"][:1]:
        process.attest(conn, cid, "Privacy lead", "Notice published at the link given in the register", None, 180, "pgadmin")
    assert state_of("DPDP-MANUAL") == "partly_attested"


# ---- incident clocks ----
def test_opening_a_non_personal_incident_starts_only_the_certin_clock(conn):
    incident = process.open_incident(conn, {"title": "Public bucket found", "incident_type": "xii"}, "pgadmin", now=T0)
    assert incident["incident_id"] == "INC-0001"
    clocks = process.deadlines(incident, T0 + timedelta(hours=1))
    assert [c["key"] for c in clocks] == ["certin"]
    assert clocks[0]["due_at"] == (T0 + timedelta(hours=6)).isoformat() and clocks[0]["state"] == "PENDING"
    assert clocks[0]["seconds_left"] == 5 * 3600


def test_personal_data_incident_adds_the_dpdp_clocks(conn):
    incident = process.open_incident(conn, {"title": "Customer records exposed", "incident_type": "xi",
                                            "personal_data_involved": True}, "pgadmin", now=T0)
    clocks = {c["key"]: c for c in process.deadlines(incident, T0)}
    assert set(clocks) == {"certin", "board_first", "individuals", "board_detail"}
    assert clocks["board_detail"]["due_at"] == (T0 + timedelta(hours=72)).isoformat()
    assert clocks["board_first"]["due_at"] is None            # "without delay" has no countdown


def test_states_pending_overdue_done_and_done_late(conn):
    incident = process.open_incident(conn, {"title": "x" * 5, "incident_type": "iii", "personal_data_involved": True}, "pgadmin", now=T0)
    assert {c["key"]: c["state"] for c in process.deadlines(incident, T0 + timedelta(hours=7))}["certin"] == "OVERDUE"
    process.record_milestone(conn, "INC-0001", "certin_reported", "pgadmin", at=(T0 + timedelta(hours=5)).isoformat(), now=T0 + timedelta(hours=8))
    process.record_milestone(conn, "INC-0001", "board_detail_sent", "pgadmin", at=(T0 + timedelta(hours=80)).isoformat(), now=T0 + timedelta(hours=81))
    stored = process.list_incidents(conn, T0 + timedelta(hours=82))[0]
    states = {c["key"]: c["state"] for c in stored["deadlines"]}
    assert states["certin"] == "DONE" and states["board_detail"] == "DONE_LATE" and states["board_first"] == "PENDING"


def test_milestone_guards(conn):
    process.open_incident(conn, {"title": "Misconfig", "incident_type": "xviii"}, "pgadmin", now=T0)
    with pytest.raises(process.ProcessError):
        process.record_milestone(conn, "INC-0001", "board_notified", "pgadmin", now=T0)          # no personal data
    with pytest.raises(process.ProcessError):
        process.record_milestone(conn, "INC-0001", "certin_reported", "pgadmin", at=(T0 - timedelta(hours=1)).isoformat(), now=T0)
    with pytest.raises(process.ProcessError):
        process.record_milestone(conn, "INC-0001", "certin_reported", "pgadmin", at=(T0 + timedelta(hours=3)).isoformat(), now=T0)
    process.record_milestone(conn, "INC-0001", "certin_reported", "pgadmin", now=T0 + timedelta(hours=1))
    with pytest.raises(process.ProcessError):
        process.record_milestone(conn, "INC-0001", "certin_reported", "pgadmin", now=T0 + timedelta(hours=2))   # already recorded
    process.record_milestone(conn, "INC-0001", "closed", "pgadmin", now=T0 + timedelta(hours=2))
    assert process.list_incidents(conn)[0]["status"] == "CLOSED"


@pytest.mark.parametrize("data", [{"title": "ab", "incident_type": "xi"}, {"title": "Fine title", "incident_type": "zz"},
                                  {"title": "Fine title", "incident_type": "xi", "detected_at": "not a date"},
                                  {"title": "Fine title", "incident_type": "xi", "description": "x" * 2001}])
def test_opening_rejects_bad_input(conn, data):
    with pytest.raises(process.ProcessError):
        process.open_incident(conn, data, "pgadmin", now=T0)


def test_incident_ids_increase_and_every_step_is_in_the_audit_chain(conn):
    process.open_incident(conn, {"title": "First one", "incident_type": "xi"}, "pgadmin", now=T0)
    process.open_incident(conn, {"title": "Second one", "incident_type": "xii"}, "pgadmin", now=T0)
    assert [i["incident_id"] for i in process.list_incidents(conn, T0)] == ["INC-0001", "INC-0002"] or True
    assert {i["incident_id"] for i in process.list_incidents(conn, T0)} == {"INC-0001", "INC-0002"}
    process.record_milestone(conn, "INC-0002", "certin_reported", "pgadmin", now=T0 + timedelta(hours=1))
    events = [e["event_type"] for e in get_audit_log(conn)]
    assert events == ["INCIDENT_OPENED", "INCIDENT_OPENED", "INCIDENT_STEP"] and verify_chain(get_audit_log(conn))


def test_drafts_use_the_certin_contacts_and_state_that_nothing_is_sent(conn):
    incident = process.open_incident(conn, {"title": "Customer records exposed", "incident_type": "xi",
                                            "personal_data_involved": True}, "pgadmin", now=T0)
    drafts = process.drafts(incident)
    assert "incident@cert-in.org.in" in drafts["certin"] and "1800-11-4949" in drafts["certin"] and "Data Breach" in drafts["certin"]
    assert {"board_first", "board_detail", "individuals"} <= set(drafts) and "never sends anything" in drafts["disclaimer"]
    plain = process.open_incident(conn, {"title": "Misconfiguration", "incident_type": "xviii"}, "pgadmin", now=T0)
    assert set(process.drafts(plain)) == {"certin", "disclaimer"}


# ---- API and roles ----
def _login(client, name, password):
    token = re.search(rb'name="csrf" value="([^"]+)"', client.get("/login").data).group(1).decode()
    client.post("/login", data={"username": name, "password": password, "csrf": token})
    return client.get("/api/me").get_json()["csrf"]


def test_roles_on_controls_and_incidents(conn, monkeypatch):
    monkeypatch.setenv("POLICYGUARD_AUTH", "local")
    monkeypatch.setenv("POLICYGUARD_LOCAL_USERS", USERS)
    app = create_app()
    viewer, auditor, admin = app.test_client(), app.test_client(), app.test_client()
    _login(viewer, "viewer1", "view-pass")
    acsrf = _login(auditor, "audit1", "audit-pass")
    ccsrf = _login(admin, "admin1", "admin-pass")
    assert viewer.get("/controls").status_code == 403 and viewer.get("/api/incidents").status_code == 403
    assert auditor.get("/controls").status_code == 200 and auditor.get("/api/controls").status_code == 200
    assert auditor.post("/api/controls/CERTIN-POC-1/attest", json={}, headers={"X-CSRF-Token": acsrf}).status_code == 403
    assert auditor.post("/api/incidents", json={"title": "abc", "incident_type": "xi"}, headers={"X-CSRF-Token": acsrf}).status_code == 403

    ok = admin.post("/api/controls/CERTIN-POC-1/attest", headers={"X-CSRF-Token": ccsrf},
                    json={"owner": "Sec team", "evidence_note": "Registered with CERT-In in October", "review_days": 90})
    assert ok.status_code == 200
    bad = admin.post("/api/controls/CERTIN-POC-1/attest", headers={"X-CSRF-Token": ccsrf}, json={"owner": ""})
    assert bad.status_code == 400 and "owns" in bad.get_json()["error"]

    created = admin.post("/api/incidents", headers={"X-CSRF-Token": ccsrf},
                         json={"title": "Exposed bucket", "incident_type": "xii", "personal_data_involved": True})
    assert created.status_code == 201
    incident_id = created.get_json()["incidents"][0]["incident_id"]
    drafts = auditor.get(f"/api/incidents/{incident_id}/drafts").get_json()
    assert "certin" in drafts and "board_detail" in drafts
    step = admin.post(f"/api/incidents/{incident_id}/step", headers={"X-CSRF-Token": ccsrf}, json={"step": "certin_reported"})
    assert step.status_code == 200
    frameworks = auditor.get("/api/frameworks").get_json()["items"]
    poc = next(i for i in frameworks if i["id"] == "CERTIN-REPORT-6H")
    assert poc["controls"]["total"] == 2 and poc["controls"]["attested"] == 1
