// Audit trail page.
async function loadAudit() {
  const data = await getJson("/api/audit-log");
  const status = document.getElementById("chain-status");
  status.textContent = data.chain_valid ? "VALID ✔ (no tampering detected)" : "BROKEN ✘ (tampering detected)";
  status.className = data.chain_valid ? "ok" : "bad";
  if (data.entries.length === 0) { showTableMessage("audit-body", "Audit log is empty.", 6); return; }
  const rows = data.entries.map((e, i) => {
    const d = e.details || {};
    const summary = [d.rule, d.action, d.severity, d.resource_id].filter(Boolean).join(" | ");
    const tr = document.createElement("tr");
    [cell(String(i + 1)), cell(e.timestamp), cell(e.event_type), cell(summary),
      cell((e.previous_hash || "").slice(0, 16), "mono"), cell((e.entry_hash || "").slice(0, 16), "mono")]
      .forEach((c) => tr.appendChild(c));
    return tr;
  });
  document.getElementById("audit-body").replaceChildren(...rows);
}

if (document.body && document.body.dataset && document.body.dataset.page === "audit") {
  document.getElementById("verify-btn").addEventListener("click", () => loadAudit().catch((e) => showLoadError(e.message)));
  start(loadAudit, 30000);
}
