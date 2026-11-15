// Scan history page.
async function loadScans() {
  const scans = await getJson("/api/scans");
  if (!Array.isArray(scans)) throw new Error("/api/scans returned an unexpected response.");
  const ordered = scans.slice().reverse();
  drawLineChart(document.getElementById("scan-chart"), ordered.map((s) => "#" + s.id), [
    { name: "Findings detected", cls: "a", values: ordered.map((s) => s.findings_detected || 0) },
    { name: "Resources assessed", cls: "b", values: ordered.map((s) => s.resources_assessed || 0) }]);
  if (!scans.length) { showTableMessage("scan-body", "No scans recorded yet.", 8); return; }
  const rows = scans.map((s) => {
    const tr = document.createElement("tr");
    const status = document.createElement("td");
    status.appendChild(node("span", "service-status " + (s.status === "COMPLETED" ? "SUCCESS" : s.status), s.status));
    const errors = Array.isArray(s.collection_errors) ? s.collection_errors : [];
    const notes = errors.length ? errors.map((e) => (e.service || "scan") + ": " + (e.message || "")).join("; ") : "";
    [cell("#" + s.id), status, cell(formatTime(s.started_at)), cell(formatDuration(s.duration_seconds)),
      cell((s.resources_assessed ?? 0) + " / " + (s.resources_discovered ?? 0)), cell(s.findings_detected),
      cell((s.account_scope || "—") + " · " + (s.region_scope || "—")), cell(notes)].forEach((c) => tr.appendChild(c));
    return tr;
  });
  document.getElementById("scan-body").replaceChildren(...rows);
}

if (document.body && document.body.dataset && document.body.dataset.page === "scans") start(loadScans, 30000);
