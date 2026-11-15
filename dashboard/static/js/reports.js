// Reports page: lists evidence bundles saved to the shared folder (an EFS mount on AWS).
async function loadSaved() {
  const data = await getJson("/api/reports/saved");
  const body = document.getElementById("saved-body");
  body.replaceChildren();
  if (!data.enabled) {
    body.appendChild(node("p", "muted", "No shared folder is configured, so bundles are only downloaded, not saved."));
    return;
  }
  document.getElementById("saved-note").textContent = data.folder;
  if (!data.files.length) {
    body.appendChild(node("p", "muted", "Nothing saved yet. Download an evidence bundle to save a copy here."));
    return;
  }
  const wrap = node("div", "table-wrap");
  const t = document.createElement("table");
  const head = document.createElement("tr");
  ["File", "Size", "Saved (UTC)"].forEach((h) => head.appendChild(node("th", null, h)));
  const thead = document.createElement("thead");
  thead.appendChild(head);
  const tbody = document.createElement("tbody");
  data.files.forEach((f) => {
    const tr = document.createElement("tr");
    [cell(f.name, "mono"), cell(Math.max(1, Math.round(f.bytes / 1024)) + " KiB"), cell(formatTime(f.modified))].forEach((c) => tr.appendChild(c));
    tbody.appendChild(tr);
  });
  t.append(thead, tbody);
  wrap.appendChild(t);
  body.appendChild(wrap);
}

if (document.body && document.body.dataset && document.body.dataset.page === "reports") start(loadSaved, 30000);
