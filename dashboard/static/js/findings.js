// Findings page: filters, table, expandable evidence. Requires common.js.
let currentViolations = [];

function evidenceField(container, label, value, preformatted) {
  const section = node("section", "evidence-field");
  const content = document.createElement(preformatted ? "pre" : "p");
  content.textContent = value == null || value === "" ? "Not available" :
    (typeof value === "object" ? JSON.stringify(value, null, 2) : String(value));
  section.append(node("h4", null, label), content);
  container.appendChild(section);
}

function renderEvidence(container, evidence) {
  if (!Array.isArray(evidence) || evidence.length === 0) {
    container.textContent = "Evidence not available for this finding.";
    return;
  }
  evidence.forEach((item, index) => {
    const entry = node("article", "evidence-entry");
    if (evidence.length > 1) entry.appendChild(node("h3", null, "Evidence record " + (index + 1)));
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
      "Collection: " + (item.collection_status || "Not available"),
      "SHA-256: " + (item.evidence_sha256 || "Not available")].join("\n"));
    evidenceField(entry, "Recommended corrective action", item.recommended_action, true);
    container.appendChild(entry);
  });
}

function filterValue(id, fallback) {
  const control = document.getElementById(id);
  return control ? control.value : fallback;
}

function matchesStatus(finding, selected) {
  if (selected === "ALL") return true;
  if (selected === "OPEN") return finding.status !== "RESOLVED";
  return finding.status === selected;
}

function regulationCell(finding) {
  const td = cell(finding.clause, "reg-cell");
  const obligations = Array.isArray(finding.obligations) ? finding.obligations : [];
  if (obligations.length) {
    const row = node("div", "chip-row");
    obligations.forEach((ob) => {
      const chip = node("span", "chip" + (ob.in_force === "upcoming" ? " upcoming" : ""), ob.id);
      chip.title = ob.framework + " · " + ob.citation + (ob.in_force === "upcoming" ? " · not yet in force" : "");
      row.appendChild(chip);
    });
    td.appendChild(row);
  }
  return td;
}

function renderViolations() {
  const tbody = document.getElementById("violations-body");
  const query = filterValue("violation-search", "").trim().toLocaleLowerCase();
  const severity = filterValue("violation-severity", "ALL");
  const status = filterValue("violation-status", "ALL");
  const framework = filterValue("violation-framework", "ALL");

  if (currentViolations.length === 0) {
    showTableMessage("violations-body", "No finding history is available yet.", 9);
    return;
  }
  const matches = currentViolations.filter((v) => {
    if (severity !== "ALL" && v.severity !== severity) return false;
    if (!matchesStatus(v, status)) return false;
    if (framework !== "ALL" && !(v.obligations || []).some((o) => o.framework === framework)) return false;
    const remediation = v.remediation || {};
    const searchable = [v.rule, v.resource_id, v.clause, remediation.action, remediation.message]
      .filter((value) => value != null).join(" ").toLocaleLowerCase();
    return searchable.includes(query);
  });
  const count = document.getElementById("findings-count");
  if (count) count.textContent = matches.length + " of " + currentViolations.length + " shown";
  if (matches.length === 0) {
    showTableMessage("violations-body", "No findings match the current filters.", 9);
    return;
  }

  const rows = matches.map((v) => {
    const r = v.remediation || {};
    const mode = r.dry_run === false ? "LIVE" : "DRY-RUN";
    const control = document.createElement("td");
    if (v.evidence_available === true) {
      const button = node("button", "evidence-toggle", "View evidence");
      button.type = "button";
      button.setAttribute("aria-expanded", "false");
      button.setAttribute("aria-controls", "evidence-panel-" + v.id);
      control.appendChild(button);
    } else {
      control.textContent = "No evidence available";
      control.className = "evidence-unavailable";
    }
    const cells = [statusBadge(v.status), badge(v.severity), control, cell(v.rule), cell(v.resource_id, "mono"),
      cell(formatTime(v.first_detected || v.detected_at), "nowrap"), cell(formatTime(v.last_detected), "nowrap"), regulationCell(v),
      cell(r.action ? mode + ": " + (r.message || r.action) : "—", "rem-cell")];
    return { finding: v, cells, button: control.firstElementChild };
  });

  const rendered = rows.map(({ finding, cells, button }) => {
    const tr = document.createElement("tr");
    cells.forEach((item) => tr.appendChild(item));
    if (!button) return [tr];
    const detailRow = node("tr", "evidence-detail-row");
    const detailCell = document.createElement("td");
    detailCell.colSpan = 9;
    const panel = node("div", "evidence-panel");
    panel.id = "evidence-panel-" + finding.id;
    detailCell.appendChild(panel);
    detailRow.appendChild(detailCell);
    let loaded = false;
    button.addEventListener("click", async () => {
      if (button.getAttribute("aria-expanded") === "true") {
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

function populateFrameworkFilter() {
  const select = document.getElementById("violation-framework");
  if (!select) return;
  const names = new Set();
  currentViolations.forEach((v) => (v.obligations || []).forEach((o) => names.add(o.framework)));
  const selected = select.value;
  select.replaceChildren(...["ALL"].concat(Array.from(names).sort()).map((name) => {
    const option = node("option", null, name === "ALL" ? "All" : name);
    option.value = name;
    return option;
  }));
  if (names.has(selected)) select.value = selected;
}

async function loadFindings() {
  const findings = await getJson("/api/findings");
  if (!Array.isArray(findings)) {
    currentViolations = [];
    showTableMessage("violations-body", "Findings could not be displayed because the API response was invalid.", 9);
    throw new Error("/api/findings returned an unexpected response (expected a JSON array).");
  }
  currentViolations = findings;
  populateFrameworkFilter();
  // Do not collapse evidence the reader has open while the background refresh runs.
  const open = typeof document.querySelector === "function" && document.querySelector('.evidence-toggle[aria-expanded="true"]');
  if (!open) renderViolations();
}

if (document.body && document.body.dataset && document.body.dataset.page === "findings") {
  ["violation-search"].forEach((id) => document.getElementById(id).addEventListener("input", renderViolations));
  ["violation-severity", "violation-status", "violation-framework"].forEach(
    (id) => document.getElementById(id).addEventListener("change", renderViolations));
  start(loadFindings, 30000);
}
