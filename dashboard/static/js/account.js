// AWS account page: see which account is monitored, connect another one with access keys, switch, log out.
// Values from AWS are written with textContent only. Secrets are cleared from the form after every attempt.
const isAdmin = document.body.dataset.role === "admin";

function showMessage(text, kind) {
  const box = document.getElementById("account-msg");
  box.textContent = text || "";
  box.className = "banner " + (kind === "ok" ? "banner-ok" : "banner-bad");
  box.hidden = !text;
  // The message is at the top of the page but the form is at the bottom: bring it into view.
  if (text) box.scrollIntoView({ block: "center", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

function renderNow(current) {
  const state = document.getElementById("now-state");
  state.replaceChildren(
    current.connected
      ? pill(current.state === "session" ? "Keys entered here" : "Default credentials", "ok")
      : pill("Disconnected", "warn"));
  document.getElementById("now-id").textContent = current.connected ? current.account_id : "No account connected";
  document.getElementById("now-arn").textContent = current.arn || "—";
  document.getElementById("now-region").textContent = current.region || "—";
  document.getElementById("now-source").textContent = current.source
    ? current.source + (current.key_hint ? " (key " + current.key_hint + ")" : "") : "—";
  document.getElementById("now-note").textContent = current.message || (current.state === "default"
    ? "Using the AWS credentials this server started with. Logging out pauses scans; it does not delete your credentials file."
    : "");
}

function actionButton(label, onClick, extraClass) {
  const button = node("button", "btn " + (extraClass || ""), label);
  button.type = "button";
  button.addEventListener("click", onClick);
  return button;
}

function renderRows(snapshot) {
  const body = document.getElementById("account-rows");
  const rows = snapshot.connections;
  if (!rows.length) {
    showTableMessage("account-rows", "No accounts connected with keys yet. The default credentials are used until you connect one.", 7);
    return;
  }
  body.replaceChildren(...rows.map((row) => {
    const tr = document.createElement("tr");
    const actions = document.createElement("td");
    if (isAdmin && snapshot.switching.allowed) {
      if (!row.active) actions.appendChild(actionButton("Switch to this", () => run("/api/account/switch", { account_id: row.account_id })));
      actions.appendChild(actionButton("Forget", () => forget(row), "btn-quiet"));
    }
    tr.append(cell(row.account_id, "mono"), cell(row.arn, "mono"), cell(row.region), cell(row.key_hint, "mono"),
      cell(formatTime(row.connected_at)));
    const status = document.createElement("td");
    status.appendChild(row.active ? pill("Monitoring", "ok") : pill("Connected", "muted"));
    tr.append(status, actions);
    return tr;
  }));
}

function render(snapshot) {
  renderNow(snapshot.current);
  renderRows(snapshot);
  const allowed = snapshot.switching.allowed;
  const actions = document.getElementById("now-actions");
  actions.hidden = !(isAdmin && allowed);
  document.getElementById("btn-disconnect").hidden = snapshot.current.state === "none";
  document.getElementById("btn-default").hidden = snapshot.current.state === "default";

  const form = document.getElementById("connect-form");
  const blocked = document.getElementById("connect-blocked");
  const canChange = isAdmin && allowed;
  form.hidden = !canChange;
  blocked.hidden = canChange;
  blocked.textContent = !isAdmin ? "Only admins can change the monitored account." : (snapshot.switching.reason || "");

  const select = document.getElementById("f-region");
  if (!select.options.length) {
    snapshot.regions.forEach((region) => {
      const option = node("option", "", region.id + " — " + region.name);
      option.value = region.id;
      select.appendChild(option);
    });
    select.value = snapshot.current.region && snapshot.regions.some((r) => r.id === snapshot.current.region)
      ? snapshot.current.region : "ap-south-1";
  }
}

async function load() {
  render(await getJson("/api/account"));
}

async function run(url, body, successMessage) {
  showMessage("");
  try {
    render(await postJson(url, body || {}));
    await refreshAccountChip();
    if (successMessage) showMessage(successMessage, "ok");
  } catch (err) {
    if (err.message !== "Signed out") showMessage(err.message);
  }
}

function forget(row) {
  if (!window.confirm("Forget account " + row.account_id + "? Its stored keys are removed from this server.")) return;
  run("/api/account/disconnect", { account_id: row.account_id });
}

document.getElementById("btn-disconnect").addEventListener("click", () => {
  if (!window.confirm("Log out of this AWS account? Scans are paused until you connect an account again.")) return;
  run("/api/account/disconnect", {}, "Logged out. No AWS account is being monitored.");
});
document.getElementById("btn-default").addEventListener("click", () =>
  run("/api/account/default", {}, "Back to the default credentials."));

document.getElementById("connect-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const button = document.getElementById("btn-connect");
  const body = {
    access_key_id: form.access_key_id.value, secret_access_key: form.secret_access_key.value,
    session_token: form.session_token.value, region: form.region.value,
  };
  button.disabled = true;
  button.textContent = "Checking with AWS…";
  try {
    await run("/api/account/connect", body, "Connected. Now monitoring this account. Run a scan to see its findings.");
  } finally {
    // Never leave a secret sitting in the form, whether or not the attempt worked.
    form.access_key_id.value = ""; form.secret_access_key.value = ""; form.session_token.value = "";
    button.disabled = false;
    button.textContent = "Verify with AWS and monitor this account";
  }
});

start(load, 0);
