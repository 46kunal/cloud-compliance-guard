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

async function loadAnchors() {
  const data = await getJson("/api/audit-anchors");
  const status = document.getElementById("anchor-status");
  const body = document.getElementById("anchor-body");
  body.replaceChildren();
  if (!data.configured) {
    status.textContent = "NOT CONFIGURED";
    status.className = "";
    body.appendChild(node("p", "muted", "Anchoring needs an S3 Object Lock bucket and a KMS signing key. It is set up by the AWS deployment."));
    return;
  }
  if (data.error) { status.textContent = "UNAVAILABLE"; status.className = "bad"; body.appendChild(node("p", "bad", data.error)); return; }
  const labels = { VERIFIED: "VERIFIED ✔ (chain matches every signed receipt)", MISMATCH: "MISMATCH ✘ (the chain does not match the receipts)",
    NO_ANCHORS: "NO RECEIPTS YET (the next scan with new events writes one)" };
  status.textContent = labels[data.status] || data.status;
  status.className = data.status === "VERIFIED" ? "ok" : data.status === "MISMATCH" ? "bad" : "";
  document.getElementById("anchor-note").textContent = data.lock_mode + " lock · " + data.retention_days + " days · " +
    data.entries_after_last_anchor + " entries since the last anchor";
  if (!data.anchors.length) return;
  const wrap = node("div", "table-wrap");
  const t = document.createElement("table");
  const head = document.createElement("tr");
  ["Chain length", "Anchored", "Locked until", "Signature", "Matches chain", "Head hash"].forEach((h) => head.appendChild(node("th", null, h)));
  const thead = document.createElement("thead");
  thead.appendChild(head);
  const tbody = document.createElement("tbody");
  data.anchors.slice().reverse().forEach((a) => {
    const tr = document.createElement("tr");
    const sig = document.createElement("td");
    sig.appendChild(pill(a.signature_valid ? "valid" : "INVALID", a.signature_valid ? "ok" : "bad"));
    const match = document.createElement("td");
    match.appendChild(pill(a.matches_chain ? "yes" : "NO", a.matches_chain ? "ok" : "bad"));
    [cell(a.sequence), cell(formatTime(a.anchored_at)), cell(formatTime(a.locked_until)), sig, match,
      cell((a.head_hash || "").slice(0, 16), "mono")].forEach((c) => tr.appendChild(c));
    tbody.appendChild(tr);
    if (a.reason) {
      const why = document.createElement("tr");
      const td = cell(a.reason, "bad");
      td.colSpan = 6;
      why.appendChild(td);
      tbody.appendChild(why);
    }
  });
  t.append(thead, tbody);
  wrap.appendChild(t);
  body.appendChild(wrap);
}

async function loadAuditPage() {
  await Promise.all([loadAudit(), loadAnchors()]);
}

if (document.body && document.body.dataset && document.body.dataset.page === "audit") {
  document.getElementById("verify-btn").addEventListener("click", () => loadAuditPage().catch((e) => showLoadError(e.message)));
  start(loadAuditPage, 30000);
}
