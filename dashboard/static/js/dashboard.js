// Fetches the JSON API routes and renders them. All values go through textContent
// because resource names come from AWS and must not be trusted as HTML.
const REFRESH_MS = 10000;
let currentViolations = [];

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text == null ? "—" : String(text);
  if (className) td.className = className;
  return td;
}

function badge(severity) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  const value = ["HIGH", "MEDIUM", "LOW"].includes(severity) ? severity : "UNKNOWN";
  span.className = "badge " + value;
  span.textContent = value;
  td.appendChild(span);
  return td;
}

function showTableMessage(tbodyId, message, colspan) {
  const tbody = document.getElementById(tbodyId);
  const tr = document.createElement("tr");
  const td = cell(message);
  td.colSpan = colspan;
  tr.appendChild(td);
  tbody.replaceChildren(tr);
}

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(url + " returned " + res.status);
  return res.json();
}

function createViolationControls() {
  if (document.getElementById("violation-search")) return;
  const heading = Array.from(document.querySelectorAll("main h2")).find((el) => el.textContent.trim() === "Violations");
  if (!heading) return;

  const controls = document.createElement("div");
  controls.className = "violation-controls";

  const searchLabel = document.createElement("label");
  searchLabel.textContent = "Search violations ";
  const search = document.createElement("input");
  search.id = "violation-search";
  search.type = "search";
  search.setAttribute("aria-label", "Search by rule, resource ID, clause, or remediation");
  search.autocomplete = "off";
  searchLabel.appendChild(search);

  const severityLabel = document.createElement("label");
  severityLabel.textContent = "Severity ";
  const severity = document.createElement("select");
  severity.id = "violation-severity";
  severity.setAttribute("aria-label", "Filter violations by severity");
  [["ALL", "All"], ["HIGH", "HIGH"], ["MEDIUM", "MEDIUM"], ["LOW", "LOW"]].forEach(([value, label]) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    severity.appendChild(option);
  });
  severityLabel.appendChild(severity);
  controls.append(searchLabel, severityLabel);
  heading.insertAdjacentElement("afterend", controls);

  search.addEventListener("input", renderViolations);
  severity.addEventListener("change", renderViolations);
}

function renderViolations() {
  const tbody = document.getElementById("violations-body");
  const search = document.getElementById("violation-search");
  const severity = document.getElementById("violation-severity");
  const query = search ? search.value.trim().toLocaleLowerCase() : "";
  const selectedSeverity = severity ? severity.value : "ALL";

  if (currentViolations.length === 0) {
    showTableMessage("violations-body", "No violations — fully compliant.", 5);
    return;
  }

  const matches = currentViolations.filter((v) => {
    if (selectedSeverity !== "ALL" && v.severity !== selectedSeverity) return false;
    const remediation = v.remediation || {};
    const searchable = [v.rule, v.resource_id, v.clause, remediation.action, remediation.message]
      .filter((value) => value != null)
      .join(" ")
      .toLocaleLowerCase();
    return searchable.includes(query);
  });

  if (matches.length === 0) {
    showTableMessage("violations-body", "No violations match the current search and severity filter.", 5);
    return;
  }

  const rows = matches.map((v) => {
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
  const rendered = rows.map((cells) => {
    const tr = document.createElement("tr");
    cells.forEach((item) => tr.appendChild(item));
    return tr;
  });
  tbody.replaceChildren(...rendered);
}

function setScanMessage(message, isError = false) {
  const messageNode = document.getElementById("scan-feedback");
  if (!messageNode) return;
  messageNode.textContent = message;
  messageNode.className = isError ? "bad" : "ok";
  messageNode.hidden = !message;
}

function ensureScanFeedback() {
  const scanBar = document.querySelector(".scan-bar");
  const button = document.getElementById("scan-now");
  if (!scanBar || !button || document.getElementById("scan-feedback")) return;
  const message = document.createElement("span");
  message.id = "scan-feedback";
  message.setAttribute("role", "status");
  message.setAttribute("aria-live", "polite");
  message.hidden = true;
  scanBar.insertBefore(message, button);
}

function ensureLoadError() {
  let error = document.getElementById("data-load-error");
  if (!error) {
    error = document.createElement("p");
    error.id = "data-load-error";
    error.className = "bad";
    error.setAttribute("role", "status");
    document.querySelector("main").prepend(error);
  }
  return error;
}

async function loadDashboard() {
  const [score, violations] = await Promise.all([
    getJson("/api/compliance-score"),
    getJson("/api/violations"),
  ]);
  document.getElementById("score").textContent = score.score + "%";
  document.getElementById("resources").textContent = score.resources_scanned;
  document.getElementById("total").textContent = score.total_violations;
  document.getElementById("last-scan").textContent = score.last_scan || "never";
  document.getElementById("severity-breakdown").textContent =
    ["HIGH", "MEDIUM", "LOW"].map((s) => s + ": " + (score.by_severity[s] || 0)).join("  ·  ");

  currentViolations = Array.isArray(violations) ? violations : [];
  renderViolations();
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
      cell((e.previous_hash || "").slice(0, 16), "mono"),
      cell((e.entry_hash || "").slice(0, 16), "mono"),
    ];
  });
  const tbody = document.getElementById("audit-body");
  if (rows.length === 0) {
    showTableMessage("audit-body", "Audit log is empty.", 6);
    return;
  }
  tbody.replaceChildren(...rows.map((cells) => {
    const tr = document.createElement("tr");
    cells.forEach((item) => tr.appendChild(item));
    return tr;
  }));
}

function start(loader) {
  const run = () => loader().then(() => {
    const error = document.getElementById("data-load-error");
    if (error) error.remove();
  }).catch((err) => {
    ensureLoadError().textContent = "Failed to load data: " + err.message;
  });
  run();
  setInterval(run, REFRESH_MS);
}

async function scanNow(button) {
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = "Scanning AWS…";
  setScanMessage("Scanning AWS resources…");
  try {
    const res = await fetch("/api/scan", { method: "POST" });
    if (!res.ok) throw new Error("Scan returned " + res.status);
    const result = await res.json();
    await loadDashboard();
    const counts = [
      ["resources", "resources"],
      ["violations", "violations"],
      ["new", "new"],
      ["resolved", "resolved"],
    ].filter(([key]) => result[key] != null).map(([key, label]) => result[key] + " " + label);
    setScanMessage("Scan complete" + (counts.length ? " · " + counts.join(" · ") : "."));
  } catch (err) {
    setScanMessage("Scan failed: " + err.message, true);
  } finally {
    button.disabled = false;
    button.textContent = originalText;
  }
}

if (window.PAGE === "dashboard") {
  createViolationControls();
  ensureScanFeedback();
  start(loadDashboard);
  const button = document.getElementById("scan-now");
  button.addEventListener("click", () => scanNow(button));
}
if (window.PAGE === "audit") start(loadAudit);
