// Admin users page (Cognito). Values from the API are written with textContent only.
function userMessage(text, ok) {
  const box = document.getElementById("user-msg");
  box.textContent = text || "";
  box.className = "banner " + (ok ? "banner-ok" : "banner-bad");
  box.hidden = !text;
  if (text) box.scrollIntoView({ block: "center" });
}

async function userPost(url, body) {
  const csrf = await getCsrf();
  const res = await fetch(url, { method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body || {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || (url + " returned " + res.status));
  return data;
}

function userButton(label, handler, extra) {
  const button = node("button", "btn " + (extra || ""), label);
  button.type = "button";
  button.addEventListener("click", async () => {
    button.disabled = true;
    try { userMessage(""); await handler(); await loadUsers(); } catch (e) { userMessage(e.message); } finally { button.disabled = false; }
  });
  return button;
}

async function loadUsers() {
  const data = await getJson("/api/users");
  if (data.error) throw new Error(data.error);
  document.getElementById("user-mode").textContent = data.managed ? "Amazon Cognito" : "Development logins (read-only)";
  document.getElementById("user-add").hidden = !data.managed;
  if (data.note) document.getElementById("user-lead").textContent = data.note;
  const rows = data.users.map((u) => {
    const tr = document.createElement("tr");
    const role = document.createElement("td");
    if (data.managed && u.username !== data.me) {
      const select = node("select");
      data.roles.forEach((r) => { const o = node("option", null, r); o.value = r; select.appendChild(o); });
      select.value = u.role;
      select.setAttribute("aria-label", "Role for " + u.username);
      select.addEventListener("change", async () => {
        try { userMessage(""); await userPost("/api/users/" + encodeURIComponent(u.username) + "/role", { role: select.value }); await loadUsers(); }
        catch (e) { userMessage(e.message); await loadUsers(); }
      });
      role.appendChild(select);
    } else {
      role.appendChild(node("span", "role-badge role-" + u.role, u.role));
    }
    const status = document.createElement("td");
    status.appendChild(u.enabled ? pill(u.status === "FORCE_CHANGE_PASSWORD" ? "Invited" : (u.status === "LOCAL" ? "Local" : "Active"),
      u.status === "FORCE_CHANGE_PASSWORD" ? "warn" : "ok") : pill("Disabled", "muted"));
    const actions = document.createElement("td");
    if (data.managed && u.username !== data.me) {
      const base = "/api/users/" + encodeURIComponent(u.username);
      if (u.status === "FORCE_CHANGE_PASSWORD") actions.appendChild(userButton("Resend invite", () => userPost(base + "/resend")));
      actions.appendChild(userButton(u.enabled ? "Disable" : "Enable", () => userPost(base + (u.enabled ? "/disable" : "/enable"))));
      actions.appendChild(userButton("Delete", async () => {
        if (!window.confirm("Delete " + u.username + "? This cannot be undone.")) return;
        await userPost(base + "/delete");
      }, "btn-quiet"));
    } else if (u.username === data.me) {
      actions.appendChild(node("span", "muted", "You"));
    }
    tr.append(cell(u.username, "mono"), cell(u.email), role, status, actions);
    return tr;
  });
  document.getElementById("user-rows").replaceChildren(...(rows.length ? rows : [(() => { const tr = document.createElement("tr"); const td = cell("No users."); td.colSpan = 5; tr.appendChild(td); return tr; })()]));
}

if (document.body.dataset.page === "users") {
  document.getElementById("user-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      userMessage("");
      await userPost("/api/users", { username: document.getElementById("u-name").value,
        email: document.getElementById("u-email").value, role: document.getElementById("u-role").value });
      document.getElementById("user-form").reset();
      userMessage("User created. Cognito emailed the temporary password.", true);
      await loadUsers();
    } catch (e) { userMessage(e.message); }
  });
  start(loadUsers, 30000);
}
