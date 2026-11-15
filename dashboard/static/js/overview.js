// Overview page: score, trend, severity/rule breakdown, service coverage, framework glance, scan button.
const VALID_SERVICE_STATES = ["SUCCESS", "PARTIAL", "FAILED", "NOT_SCANNED"];

function setText(id, text) {
  const target = document.getElementById(id);
  if (target) target.textContent = text;
}

function renderCoverage(scan, errors) {
  const services = document.getElementById("service-statuses");
  services.replaceChildren();
  const statuses = scan ? scan.service_statuses : {};
  if (scan && !isRecord(statuses)) errors.push("/api/compliance-score returned invalid scan.service_statuses metadata.");
  Object.entries(isRecord(statuses) ? statuses : {}).forEach(([name, detail]) => {
    if (!isRecord(detail) || !VALID_SERVICE_STATES.includes(detail.status)) {
      errors.push("/api/compliance-score returned invalid collection status for " + name + ".");
      return;
    }
    const row = node("div", "service-row");
    row.append(node("span", null, name.toUpperCase()), node("span", "service-status " + detail.status, detail.status));
    services.appendChild(row);
  });
  if (!services.childElementCount) services.appendChild(node("p", "muted", "No scan has run yet."));

  const box = document.getElementById("collection-errors");
  box.replaceChildren();
  const list = scan && Array.isArray(scan.collection_errors) ? scan.collection_errors : [];
  const valid = list.filter((item) => isRecord(item) && typeof item.service === "string" && typeof item.message === "string");
  if (scan && !Array.isArray(scan.collection_errors)) errors.push("/api/compliance-score returned invalid scan.collection_errors metadata.");
  if (valid.length) {
    box.appendChild(node("strong", null, "Collection errors"));
    const ul = node("ul");
    valid.forEach((item) => ul.appendChild(node("li", null, item.service.toUpperCase() + ": " + item.message)));
    box.appendChild(ul);
  }
  box.hidden = valid.length === 0;
}

function renderWarning(scan) {
  const warning = document.getElementById("assessment-warning");
  if (!scan) {
    warning.textContent = "Not assessed: no scan results yet. Run a scan to collect AWS configuration.";
  } else if (scan.status === "FAILED") {
    warning.textContent = "The latest scan failed. Existing findings were kept and were not resolved by it.";
  } else if (scan.status === "PARTIAL") {
    warning.textContent = "Incomplete assessment: only successfully collected services count toward coverage or can resolve findings.";
  } else {
    warning.hidden = true;
    return;
  }
  warning.hidden = false;
}

async function loadOverview() {
  const [scoreR, scansR, fwR] = await Promise.allSettled([
    getJson("/api/compliance-score"), getJson("/api/scans"), getJson("/api/frameworks")]);
  const errors = [];
  if (scoreR.status !== "fulfilled") throw new Error("/api/compliance-score: " + scoreR.reason.message);
  const score = scoreR.value, scan = score.scan;

  drawGauge(document.getElementById("score-gauge"), score.score);
  setText("score-note", score.score == null
    ? "No successfully assessed resources yet."
    : "Share of the " + score.resources_assessed + " assessed resources with no open finding.");
  setText("total", score.total_violations);
  setText("severity-breakdown", ["HIGH", "MEDIUM", "LOW"].map((s) => s + " " + (score.by_severity[s] || 0)).join(" · "));
  setText("resources-assessed", score.resources_assessed);
  setText("resources-note", score.scan_coverage == null ? "" : score.scan_coverage + "% of " + score.resources_discovered + " discovered");
  const status = document.getElementById("scan-status");
  status.textContent = scan ? scan.status : "NOT RUN";
  status.className = "kpi-value status-text " + (scan ? scan.status : "");
  setText("last-scan", score.last_scan ? "Finished " + formatTime(score.last_scan.replace(" UTC", "")) : "Never scanned");
  setText("assessment-scope", scan ? "Account " + scan.account_scope + " · " + scan.region_scope : "");
  renderWarning(scan);
  renderCoverage(scan, errors);

  const rules = Object.entries(score.by_rule || {}).sort((a, b) => b[1] - a[1]);
  drawBars(document.getElementById("rule-bars"), rules);

  if (scansR.status === "fulfilled" && Array.isArray(scansR.value)) {
    const ordered = scansR.value.slice().reverse();
    drawLineChart(document.getElementById("trend-chart"), ordered.map((s) => "#" + s.id), [
      { name: "Findings detected", cls: "a", values: ordered.map((s) => s.findings_detected || 0) },
      { name: "Resources assessed", cls: "b", values: ordered.map((s) => s.resources_assessed || 0) }]);
    setText("trend-note", ordered.length + " scan" + (ordered.length === 1 ? "" : "s"));
  } else {
    errors.push("/api/scans: could not load scan history");
  }

  const glance = document.getElementById("framework-glance");
  glance.replaceChildren();
  if (fwR.status === "fulfilled" && fwR.value.items) {
    const byFramework = {};
    fwR.value.items.forEach((item) => {
      const entry = byFramework[item.framework] || (byFramework[item.framework] = { open: 0, assessed: 0, total: 0 });
      entry.total += 1;
      entry.open += item.open_findings;
      if (item.state !== "not_assessed") entry.assessed += 1;
    });
    Object.entries(byFramework).forEach(([name, entry]) => {
      const row = node("div", "glance-row");
      const kind = entry.open ? "bad" : entry.assessed ? "ok" : "muted";
      const text = entry.open ? entry.open + " open" : entry.assessed ? "No open findings" : "Not assessed";
      row.append(node("span", null, name), pill(text, kind));
      glance.appendChild(row);
    });
  }
  if (errors.length) throw new Error(errors.join(" | "));
}

function setScanMessage(message, isError) {
  const target = document.getElementById("scan-feedback");
  target.textContent = message;
  target.className = isError ? "pill pill-bad" : "pill pill-ok";
  target.hidden = !message;
}

async function scanNow(button) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = "Scanning AWS…";
  setScanMessage("");
  try {
    const result = await postJson("/api/scan");
    await loadOverview();
    const counts = [["resources_discovered", "discovered"], ["resources_assessed", "assessed"], ["violations", "findings"],
      ["new", "new"], ["resolved", "resolved"]].filter(([key]) => result[key] != null).map(([key, name]) => result[key] + " " + name);
    setScanMessage((result.status || "Scan") + (counts.length ? " · " + counts.join(" · ") : ""),
      result.status === "FAILED" || result.status === "PARTIAL");
  } catch (err) {
    setScanMessage("Scan failed: " + err.message, true);
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

if (document.body && document.body.dataset && document.body.dataset.page === "index") {
  const button = document.getElementById("scan-now");
  if (document.body.dataset.role === "admin") {
    button.hidden = false;
    button.addEventListener("click", () => scanNow(button));
  } else {
    document.getElementById("scan-help").textContent = "Scans run on a schedule. Ask an admin to run one on demand.";
  }
  start(loadOverview);
}
