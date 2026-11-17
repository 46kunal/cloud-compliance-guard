// Monitored accounts page (cross-account roles). Values from the API are written with textContent only.
const canEdit = document.body.dataset.role === "admin";

function acctMessage(text, ok) {
  const box = document.getElementById("acct-msg");
  box.textContent = text || "";
  box.className = "banner " + (ok ? "banner-ok" : "banner-bad");
  box.hidden = !text;
  if (text) box.scrollIntoView({ block: "center" });
}

async function postJsonBody(url, body) {
  const csrf = await getCsrf();
  const res = await fetch(url, { method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body || {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || data.detail || (url + " returned " + res.status));
  return data;
}

function showSteps(instructions) {
  document.getElementById("steps-panel").hidden = false;
  document.getElementById("steps-account").textContent = instructions.account_id;
  document.getElementById("steps-command").textContent = instructions.deploy_command;
  document.getElementById("steps-template").href = instructions.template_url;
  document.getElementById("steps-panel").scrollIntoView({ block: "start" });
}

function rowButton(label, handler, extra) {
  const button = node("button", "btn " + (extra || ""), label);
  button.type = "button";
  button.addEventListener("click", async () => {
    button.disabled = true;
    try { acctMessage(""); await handler(); await loadAccounts(); } catch (e) { acctMessage(e.message); } finally { button.disabled = false; }
  });
  return button;
}

function statusPill(account) {
  if (account.status === "ACTIVE" && account.enabled) return pill("Active", "ok");
  if (account.status === "ACTIVE") return pill("Disabled", "muted");
  return pill("Needs verification", "warn");
}

async function loadAccounts() {
  const data = await getJson("/api/monitored-accounts");
  document.getElementById("home-note").textContent = data.home_account_id ? "PolicyGuard runs in " + data.home_account_id : "";
  document.getElementById("add-panel").hidden = !canEdit;
  const rows = [];
  rows.push(row("This account (home)", data.home_account_id || "—", "—", pill("Always scanned", "ok"), "—", null));
  data.accounts.forEach((a) => {
    const actions = document.createElement("td");
    if (canEdit) {
      if (a.status !== "ACTIVE") {
        actions.appendChild(rowButton("Show steps", async () => {
          showSteps(await getJson("/api/monitored-accounts/" + a.account_id + "/instructions"));
        }, "btn-quiet"));
        actions.appendChild(rowButton("Verify", () => postJsonBody("/api/monitored-accounts/" + a.account_id + "/verify"), "btn-primary"));
      } else {
        if (a.enabled) {
          if (data.scan_function) actions.appendChild(rowButton("Scan now", () => postJsonBody("/api/monitored-accounts/" + a.account_id + "/scan")));
          actions.appendChild(rowButton("Disable", () => postJsonBody("/api/monitored-accounts/" + a.account_id + "/disable")));
        } else {
          actions.appendChild(rowButton("Enable", () => postJsonBody("/api/monitored-accounts/" + a.account_id + "/enable")));
        }
      }
      actions.appendChild(rowButton("Remove", async () => {
        if (!window.confirm("Remove " + a.name + "? Its stored findings are kept. Also delete the role in that account to end access.")) return;
        await postJsonBody("/api/monitored-accounts/" + a.account_id + "/delete");
      }, "btn-quiet"));
    }
    const last = a.last_scan_at ? formatTime(a.last_scan_at) + (a.last_scan_status ? " · " + a.last_scan_status : "") : "—";
    const tr = row(a.name, a.account_id, a.region, statusPill(a), last, actions);
    if (a.last_error) {
      const note = document.createElement("tr");
      const td = cell(a.last_error, "bad");
      td.colSpan = 6;
      note.appendChild(td);
      rows.push(tr, note);
    } else rows.push(tr);
  });
  document.getElementById("acct-rows").replaceChildren(...rows);
}

function row(name, id, region, statusNode, last, actions) {
  const tr = document.createElement("tr");
  const status = document.createElement("td");
  status.appendChild(statusNode);
  tr.append(cell(name), cell(id, "mono"), cell(region), status, cell(last), actions || document.createElement("td"));
  return tr;
}

if (document.body.dataset.page === "accounts") {
  document.getElementById("add-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      acctMessage("");
      const result = await postJsonBody("/api/monitored-accounts", {
        name: document.getElementById("a-name").value, account_id: document.getElementById("a-id").value,
        region: document.getElementById("a-region").value });
      document.getElementById("add-form").reset();
      document.getElementById("a-region").value = "ap-south-1";
      await loadAccounts();
      showSteps(result.instructions);
    } catch (e) { acctMessage(e.message); }
  });
  start(loadAccounts, 30000);
}
