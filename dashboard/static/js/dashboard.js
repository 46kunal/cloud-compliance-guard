// Fetches the JSON API routes and renders them. All values go through textContent (no innerHTML)
// because resource names come from AWS and must not be trusted as HTML.
const REFRESH_MS = 10000;

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function badge(severity) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  span.className = "badge " + severity;
  span.textContent = severity;
  td.appendChild(span);
  return td;
}

function fillTable(tbodyId, rows, emptyText, colspan) {
  const tbody = document.getElementById(tbodyId);
  tbody.replaceChildren();
  if (rows.length === 0) {
    const tr = document.createElement("tr");
    const td = cell(emptyText);
    td.colSpan = colspan;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  rows.forEach((cells) => {
    const tr = document.createElement("tr");
    cells.forEach((c) => tr.appendChild(c));
    tbody.appendChild(tr);
  });
}

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(url + " returned " + res.status);
  return res.json();
}

async function loadDashboard() {
  const [score, violations] = await Promise.all([
    getJson("/api/compliance-score"),
    getJson("/api/violations"),
  ]);
  document.getElementById("score").textContent = score.score + "%";
  document.getElementById("resources").textContent = score.resources_scanned;
  document.getElementById("total").textContent = score.total_violations;
  document.getElementById("severity-breakdown").textContent =
    ["HIGH", "MEDIUM", "LOW"].map((s) => s + ": " + (score.by_severity[s] || 0)).join("  ·  ");

  const rows = violations.map((v) => {
    const r = v.remediation || {};
    const mode = r.dry_run === false ? "LIVE" : "DRY-RUN";
    return [
      badge(v.severity),
      cell(v.rule),
      cell(v.resource_id, "mono"),
      cell(v.clause),
      cell(r.action ? mode + ": " + (r.message || r.action) : "—"),
    ];
  });
  fillTable("violations-body", rows, "No violations — fully compliant.", 5);
}

async function loadAudit() {
  const data = await getJson("/api/audit-log");
  const status = document.getElementById("chain-status");
  status.textContent = data.chain_valid ? "VALID ✔ (no tampering detected)" : "BROKEN ✘ (tampering detected)";
  status.className = data.chain_valid ? "ok" : "bad";

  const rows = data.entries.map((e, i) => {
    const d = e.details || {};
    const summary = [d.rule, d.action, d.severity, d.resource_id].filter(Boolean).join(" | ");
    return [
      cell(String(i + 1)),
      cell(e.timestamp),
      cell(e.event_type),
      cell(summary),
      cell(e.previous_hash.slice(0, 16), "mono"),
      cell(e.entry_hash.slice(0, 16), "mono"),
    ];
  });
  fillTable("audit-body", rows, "Audit log is empty.", 6);
}

function start(loader) {
  const run = () => loader().catch((err) => {
    document.querySelector("main").prepend(Object.assign(document.createElement("p"), {
      className: "bad",
      textContent: "Failed to load data: " + err.message,
    }));
  });
  run();
  setInterval(run, REFRESH_MS);
}

if (window.PAGE === "dashboard") start(loadDashboard);
if (window.PAGE === "audit") start(loadAudit);
