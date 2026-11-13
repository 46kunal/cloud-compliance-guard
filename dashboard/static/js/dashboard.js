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

function statusBadge(status) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  const value = ["NEW", "ACTIVE", "RESOLVED", "REOPENED"].includes(status) ? status : "UNKNOWN";
  span.className = "badge lifecycle " + value;
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

function evidenceField(container, label, value, preformatted = false) {
  const section = document.createElement("section");
  section.className = "evidence-field";
  const heading = document.createElement("h4");
  heading.textContent = label;
  const content = document.createElement(preformatted ? "pre" : "p");
  content.textContent = value == null || value === "" ? "Not available" :
    (typeof value === "object" ? JSON.stringify(value, null, 2) : String(value));
  section.append(heading, content);
  container.appendChild(section);
}

function renderEvidence(container, evidence) {
  if (!Array.isArray(evidence) || evidence.length === 0) {
    container.textContent = "Evidence not available for this finding.";
    return;
  }
  evidence.forEach((item, index) => {
    const entry = document.createElement("article");
    entry.className = "evidence-entry";
    if (evidence.length > 1) {
      const heading = document.createElement("h3");
      heading.textContent = "Evidence record " + (index + 1);
      entry.appendChild(heading);
    }
    evidenceField(entry, "Affected resource", [item.resource_id, item.resource_type, item.service].filter(Boolean).join(" · "));
    evidenceField(entry, "Account and region", [item.account_scope, item.region_scope].filter(Boolean).join(" · "));
    evidenceField(entry, "Finding", [item.rule, item.severity, item.lifecycle_status].filter(Boolean).join(" · "));
    evidenceField(entry, "Detected configuration", item.observed_configuration, true);
    evidenceField(entry, "Expected condition", item.expected_condition);
    evidenceField(entry, "Why it was flagged", item.explanation);
    evidenceField(entry, "Compliance requirement", item.compliance_mapping || "Not mapped");
    evidenceField(entry, "Evidence details", ["Detected: " + (item.detected_at || "Not available"),
      "Scan: " + (item.scan_id || "Not available"), "Scan status: " + (item.scan_status || "Not available"),
      "Source: " + (item.evidence_source || "Not available"), "Rule: " + (item.rule_reference || "Not available"),
      "Collection: " + (item.collection_status || "Not available")].join("\n"));
    evidenceField(entry, "Recommended corrective action", item.recommended_action, true);
    container.appendChild(entry);
  });
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(url + " returned " + res.status);
  return res.json();
}

function createViolationControls() {
  if (document.getElementById("violation-search")) return;
  const heading = Array.from(document.querySelectorAll("main h2")).find((el) => el.textContent.trim() === "Finding history");
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
    showTableMessage("violations-body", "No finding history is available yet.", 9);
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
    showTableMessage("violations-body", "No findings match the current search and severity filter.", 9);
    return;
  }

  const rows = matches.map((v) => {
    const r = v.remediation || {};
    const mode = r.dry_run === false ? "LIVE" : "DRY-RUN";
    const cells = [
      statusBadge(v.status),
      badge(v.severity),
    ];
    const control = document.createElement("td");
    if (v.evidence_available === true) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "evidence-toggle";
      button.textContent = "View evidence";
      button.setAttribute("aria-expanded", "false");
      button.setAttribute("aria-controls", "evidence-panel-" + v.id);
      control.appendChild(button);
    } else {
      control.textContent = "No evidence available";
      control.className = "evidence-unavailable";
    }
    cells.push(control);
    cells.push(
      cell(v.rule),
      cell(v.resource_id, "mono"),
      cell(v.first_detected || v.detected_at),
      cell(v.last_detected),
      cell(v.clause),
      cell(r.action ? mode + ": " + (r.message || r.action) : "—"),
    );
    return { finding: v, cells, button: control.firstElementChild };
  });
  const rendered = rows.map(({ finding, cells, button }) => {
    const tr = document.createElement("tr");
    cells.forEach((item) => tr.appendChild(item));
    if (!button) return [tr];
    const detailRow = document.createElement("tr");
    detailRow.className = "evidence-detail-row";
    const detailCell = document.createElement("td");
    detailCell.colSpan = 9;
    const panel = document.createElement("div");
    panel.className = "evidence-panel";
    panel.id = "evidence-panel-" + finding.id;
    detailCell.appendChild(panel);
    detailRow.appendChild(detailCell);
    let loaded = false;
    button.addEventListener("click", async () => {
      const expanded = button.getAttribute("aria-expanded") === "true";
      if (expanded) {
        detailRow.remove();
        button.setAttribute("aria-expanded", "false");
        button.textContent = "View evidence";
        return;
      }
      button.setAttribute("aria-expanded", "true");
      button.textContent = "Hide evidence";
      tr.after(detailRow);
      if (loaded) return;
      panel.textContent = "Loading evidence…";
      try {
        const response = await getJson("/api/findings/" + encodeURIComponent(finding.id) + "/evidence");
        panel.replaceChildren();
        renderEvidence(panel, response.evidence);
        loaded = true;
      } catch (error) {
        panel.textContent = "Evidence could not be loaded: " + error.message;
      }
    });
    return [tr, detailRow];
  });
  tbody.replaceChildren(...rendered.map((pair) => pair[0]));
}

function setScanMessage(message, isError = false) {
  const messageNode = document.getElementById("scan-feedback");
  if (!messageNode) return;
  messageNode.textContent = message;
  messageNode.className = isError ? "bad" : "ok";
  messageNode.hidden = !message;
}

function ensureScanFeedback() {
  const scanBar = document.querySelector(".scan-actions");
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
  const [scoreResult, findingsResult] = await Promise.allSettled([
    getJson("/api/compliance-score"),
    getJson("/api/findings"),
  ]);
  const errors = [];
  if (scoreResult.status === "fulfilled") {
    const score = scoreResult.value;
    document.getElementById("score").textContent = score.score == null ? "Not Assessed" : score.score + "%";
    document.getElementById("resources-discovered").textContent = score.resources_discovered;
    document.getElementById("resources-assessed").textContent = score.resources_assessed;
    document.getElementById("total").textContent = score.total_violations;
    document.getElementById("last-scan").textContent = score.last_scan || "never";
    const scanStatus = document.getElementById("scan-status");
    scanStatus.textContent = score.scan ? score.scan.status : "NOT RUN";
    scanStatus.className = "big status-text " + (score.scan ? score.scan.status : "NOT_SCANNED");
    document.getElementById("scan-coverage").textContent = score.scan_coverage == null ? "–" : score.scan_coverage + "%";
    document.getElementById("severity-breakdown").textContent =
      ["HIGH", "MEDIUM", "LOW"].map((s) => s + ": " + (score.by_severity[s] || 0)).join("  ·  ");

    const scan = score.scan;
    document.getElementById("assessment-scope").textContent = scan
      ? "Account " + scan.account_scope + " · Region " + scan.region_scope + " · " + (scan.services_scanned || []).length + " services attempted"
      : "No AWS assessment has completed yet.";
    const warning = document.getElementById("assessment-warning");
    if (!scan) {
      warning.textContent = "Not assessed: no scan results are available. Run a scan to collect live AWS data.";
      warning.hidden = false;
    } else if (scan.status !== "COMPLETED") {
      warning.textContent = scan.status === "FAILED"
        ? "Assessment failed. Findings were preserved and were not resolved by this scan."
        : "Incomplete assessment: only successfully collected service scopes count toward coverage or can resolve findings.";
      warning.hidden = false;
    } else {
      warning.hidden = true;
    }
    const services = document.getElementById("service-statuses");
    services.replaceChildren();
    const rawServiceStatuses = scan ? scan.service_statuses : {};
    if (scan && !isRecord(rawServiceStatuses)) {
      errors.push("/api/compliance-score returned invalid scan.service_statuses metadata.");
    }
    Object.entries(isRecord(rawServiceStatuses) ? rawServiceStatuses : {}).forEach(([name, detail]) => {
      if (!isRecord(detail) || typeof detail.status !== "string" ||
          !["SUCCESS", "PARTIAL", "FAILED", "NOT_SCANNED"].includes(detail.status)) {
        errors.push("/api/compliance-score returned invalid collection status for " + name + ".");
        return;
      }
      const row = document.createElement("div");
      row.className = "service-row";
      const service = document.createElement("span");
      service.textContent = name.toUpperCase();
      const state = document.createElement("span");
      state.className = "service-status " + detail.status;
      state.textContent = detail.status;
      row.append(service, state);
      services.appendChild(row);
    });
    if (!services.childElementCount) services.textContent = "No scan has run.";
    const collectionErrorsNode = document.getElementById("collection-errors");
    const rawCollectionErrors = scan ? scan.collection_errors : [];
    const collectionErrors = Array.isArray(rawCollectionErrors) ? rawCollectionErrors : [];
    if (scan && !Array.isArray(rawCollectionErrors)) {
      errors.push("/api/compliance-score returned invalid scan.collection_errors metadata.");
    }
    collectionErrorsNode.replaceChildren();
    const validCollectionErrors = collectionErrors.filter((item) => {
      const valid = isRecord(item) && typeof item.service === "string" && item.service.length > 0 &&
        typeof item.message === "string";
      if (!valid) errors.push("/api/compliance-score returned a collection error without service and message fields.");
      return valid;
    });
    if (validCollectionErrors.length) {
      const heading = document.createElement("strong");
      heading.textContent = "Collection errors";
      collectionErrorsNode.appendChild(heading);
      const list = document.createElement("ul");
      validCollectionErrors.forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item.service.toUpperCase() + ": " + item.message;
        list.appendChild(li);
      });
      collectionErrorsNode.appendChild(list);
      collectionErrorsNode.hidden = false;
    } else {
      collectionErrorsNode.hidden = true;
    }
  } else {
    errors.push("/api/compliance-score: " + scoreResult.reason.message);
  }

  if (findingsResult.status === "fulfilled") {
    const findings = findingsResult.value;
    if (!Array.isArray(findings)) {
      errors.push("/api/findings returned an unexpected response (expected a JSON array).");
      currentViolations = [];
      showTableMessage("violations-body", "Findings could not be displayed because the API response was invalid.", 9);
    } else {
      currentViolations = findings;
      renderViolations();
    }
  } else {
    currentViolations = [];
    showTableMessage("violations-body", "Findings could not be loaded. See the dashboard error message above.", 9);
    errors.push("/api/findings: " + findingsResult.reason.message);
  }
  if (errors.length) throw new Error(errors.join(" | "));
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
      ["resources_discovered", "discovered"],
      ["resources_assessed", "assessed"],
      ["violations", "violations"],
      ["new", "new"],
      ["resolved", "resolved"],
    ].filter(([key]) => result[key] != null).map(([key, label]) => result[key] + " " + label);
    setScanMessage((result.status || "Scan") + (counts.length ? " · " + counts.join(" · ") : "."), result.status === "FAILED" || result.status === "PARTIAL");
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
