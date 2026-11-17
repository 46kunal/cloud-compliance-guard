// Incident clock page. Values from the API are written with textContent only.
const incAdmin = document.body.dataset.role === "admin";
let incTimers = [];

function incMessage(text) {
  const box = document.getElementById("inc-msg");
  box.textContent = text || "";
  box.hidden = !text;
  if (text) box.scrollIntoView({ block: "center" });
}

async function incPost(url, body) {
  const csrf = await getCsrf();
  const res = await fetch(url, { method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body || {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || (url + " returned " + res.status));
  return data;
}

function remaining(seconds) {
  const abs = Math.abs(seconds);
  const h = Math.floor(abs / 3600), m = Math.floor((abs % 3600) / 60), s = abs % 60;
  const text = String(h).padStart(2, "0") + ":" + String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0");
  return seconds < 0 ? "overdue by " + text : text + " left";
}

function deadlineRow(incident, d) {
  const row = node("div", "glance-row");
  const left = node("div");
  left.append(node("strong", null, d.label), node("div", "fw-note", d.rule));
  const right = node("div", "fw-tags");
  if (d.state === "DONE" || d.state === "DONE_LATE") {
    right.appendChild(pill((d.state === "DONE" ? "Done " : "Done late ") + formatTime(d.done_at), d.state === "DONE" ? "ok" : "warn"));
  } else if (d.due_at) {
    const timer = pill("", d.state === "OVERDUE" ? "bad" : "warn");
    const due = new Date(d.due_at).getTime();
    const tick = () => {
      const left = Math.round((due - Date.now()) / 1000);
      timer.textContent = remaining(left);
      timer.className = "pill pill-" + (left < 0 ? "bad" : left < 3600 ? "warn" : "info");
    };
    tick();
    incTimers.push(setInterval(tick, 1000));
    right.appendChild(timer);
  } else {
    right.appendChild(pill("As soon as aware", "warn"));
  }
  if (incAdmin && !d.done_at && incident.status === "OPEN") {
    const step = { certin: "certin_reported", board_first: "board_notified", individuals: "individuals_notified", board_detail: "board_detail_sent" }[d.key];
    const button = node("button", "btn", "Mark done");
    button.type = "button";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try { incMessage(""); await incPost("/api/incidents/" + encodeURIComponent(incident.incident_id) + "/step", { step }); await loadIncidents(); }
      catch (e) { incMessage(e.message); button.disabled = false; }
    });
    right.appendChild(button);
  }
  row.append(left, right);
  return row;
}

function incidentCard(i) {
  const card = node("article", "fw-card");
  const head = node("div", "fw-card-head");
  const left = node("div");
  left.append(node("h3", null, i.incident_id + " · " + i.title), node("div", "fw-citation", "Type " + i.incident_type + ": " + i.type_text));
  const tags = node("div", "fw-tags");
  tags.append(pill(i.status, i.status === "OPEN" ? "warn" : "muted"), pill(i.personal_data_involved ? "Personal data involved" : "No personal data", i.personal_data_involved ? "bad" : "muted"));
  head.append(left, tags);
  card.appendChild(head);
  card.appendChild(node("p", "fw-note", "Detected " + formatTime(i.detected_at) + " · opened by " + i.opened_by + (i.description ? " · " + i.description : "")));
  const list = node("div", "glance");
  i.deadlines.forEach((d) => list.appendChild(deadlineRow(i, d)));
  card.appendChild(list);

  const drafts = node("details", "fw-source");
  drafts.appendChild(node("summary", null, "Draft reports (to review and file yourself)"));
  const body = node("div");
  drafts.addEventListener("toggle", async () => {
    if (!drafts.open || body.childElementCount) return;
    try {
      const data = await getJson("/api/incidents/" + encodeURIComponent(i.incident_id) + "/drafts");
      const titles = { certin: "To CERT-In", board_first: "To the Data Protection Board (first intimation)", board_detail: "To the Data Protection Board (detailed, within 72 hours)", individuals: "To affected people" };
      Object.entries(titles).forEach(([key, title]) => {
        if (!data[key]) return;
        body.append(node("h4", null, title), node("pre", "code-block", data[key]));
      });
      body.appendChild(node("p", "hint", data.disclaimer));
    } catch (e) { body.textContent = "Could not load drafts: " + e.message; }
  });
  drafts.appendChild(body);
  card.appendChild(drafts);

  if (incAdmin && i.status === "OPEN") {
    const close = node("button", "btn btn-quiet", "Close incident");
    close.type = "button";
    close.addEventListener("click", async () => {
      if (!window.confirm("Close " + i.incident_id + "? Record the notifications first.")) return;
      try { incMessage(""); await incPost("/api/incidents/" + encodeURIComponent(i.incident_id) + "/step", { step: "closed" }); await loadIncidents(); }
      catch (e) { incMessage(e.message); }
    });
    card.appendChild(close);
  }
  return card;
}

async function loadIncidents() {
  const data = await getJson("/api/incidents");
  incTimers.forEach(clearInterval);
  incTimers = [];
  document.getElementById("inc-open").hidden = !incAdmin;
  const select = document.getElementById("i-type");
  if (!select.childElementCount) {
    data.types.forEach((t) => { const o = node("option", null, t.id + ". " + (t.text.length > 90 ? t.text.slice(0, 87) + "…" : t.text)); o.value = t.id; select.appendChild(o); });
    select.value = "xi";
  }
  const list = document.getElementById("inc-list");
  list.replaceChildren();
  if (!data.incidents.length) list.appendChild(node("p", "muted", "No incidents recorded."));
  data.incidents.forEach((i) => list.appendChild(incidentCard(i)));
}

if (document.body.dataset.page === "incidents") {
  document.getElementById("inc-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      incMessage("");
      const local = document.getElementById("i-detected").value;
      await incPost("/api/incidents", { title: document.getElementById("i-title").value, incident_type: document.getElementById("i-type").value,
        detected_at: local ? new Date(local).toISOString() : null, description: document.getElementById("i-desc").value,
        personal_data_involved: document.getElementById("i-pd").value === "yes" });
      document.getElementById("inc-form").reset();
      document.getElementById("i-type").value = "xi";
      await loadIncidents();
    } catch (e) { incMessage(e.message); }
  });
  start(loadIncidents, 60000);
}
