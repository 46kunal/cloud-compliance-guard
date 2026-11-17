// Shared helpers. Every value that came from AWS or the API is written with textContent,
// never innerHTML, because resource names and tags are untrusted.
const REFRESH_MS = 15000;
const SVG_NS = "http://www.w3.org/2000/svg";
let csrfTokenValue = null;

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text == null || text === "" ? "—" : String(text);
  if (className) td.className = className;
  return td;
}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text != null) element.textContent = String(text);
  return element;
}

function pill(text, kind) {
  return node("span", "pill pill-" + kind, text);
}

function badge(severity) {
  const td = document.createElement("td");
  const value = ["HIGH", "MEDIUM", "LOW"].includes(severity) ? severity : "UNKNOWN";
  td.appendChild(node("span", "badge " + value, value));
  return td;
}

function statusBadge(status) {
  const td = document.createElement("td");
  const value = ["NEW", "ACTIVE", "RESOLVED", "REOPENED"].includes(status) ? status : "UNKNOWN";
  td.appendChild(node("span", "badge lifecycle " + value, value));
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

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return isNaN(date) ? String(value) : date.toLocaleString();
}

function formatDuration(seconds) {
  if (seconds == null) return "—";
  return seconds < 1 ? "<1 s" : seconds.toFixed(1) + " s";
}

async function getJson(url) {
  const res = await fetch(url, { credentials: "same-origin" });
  if (res.status === 401) { window.location.href = "/login"; throw new Error("Signed out"); }
  if (!res.ok) throw new Error(url + " returned " + res.status);
  return res.json();
}

async function getCsrf() {
  if (csrfTokenValue === null) {
    try { csrfTokenValue = (await getJson("/api/me")).csrf || ""; } catch (e) { csrfTokenValue = ""; }
  }
  return csrfTokenValue;
}

// body is optional; when given it is sent as JSON. Server error messages (detail/error) are surfaced to the user.
async function postJson(url, body) {
  const headers = { "X-CSRF-Token": await getCsrf() };
  const options = { method: "POST", credentials: "same-origin", headers };
  if (body !== undefined) { headers["Content-Type"] = "application/json"; options.body = JSON.stringify(body); }
  const res = await fetch(url, options);
  if (res.status === 401) { window.location.href = "/login"; throw new Error("Signed out"); }
  if (!res.ok) {
    const message = await res.json().then((data) => data && (data.detail || data.error), () => null);
    throw new Error(message || url + " returned " + res.status);
  }
  return res.json();
}

// The top-bar chip that always shows which AWS account is being monitored.
async function refreshAccountChip() {
  const chip = document.getElementById("account-chip");
  if (!chip) return;
  try {
    const { current } = await getJson("/api/account");
    const live = current.connected;
    chip.dataset.state = live ? current.state : "none";
    chip.querySelector(".account-id").textContent = live ? current.account_id : "No account";
    chip.querySelector(".account-region").textContent = live ? current.region : "disconnected";
    chip.setAttribute("aria-label", live
      ? "Monitoring AWS account " + current.account_id + " in " + current.region + ". Open the AWS account page."
      : "No AWS account connected. Open the AWS account page.");
    chip.title = live ? (current.arn || "") : (current.message || "");
  } catch (err) {
    if (err.message !== "Signed out") chip.dataset.state = "unknown";
  }
}

// ---------- small SVG charts (no external library, works offline) ----------
function svg(tag, attrs) {
  const element = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs || {}).forEach(([k, v]) => element.setAttribute(k, String(v)));
  return element;
}

function drawGauge(container, value) {
  container.replaceChildren();
  const root = svg("svg", { viewBox: "0 0 120 120", role: "presentation" });
  const radius = 48, circumference = 2 * Math.PI * radius;
  root.appendChild(svg("circle", { cx: 60, cy: 60, r: radius, fill: "none", stroke: "var(--surface-2)", "stroke-width": 12 }));
  if (value != null && value > 0) {
    const color = value >= 90 ? "var(--ok)" : value >= 60 ? "var(--medium)" : "var(--bad)";
    root.appendChild(svg("circle", { cx: 60, cy: 60, r: radius, fill: "none", stroke: color, "stroke-width": 12,
      "stroke-linecap": "round", "stroke-dasharray": (circumference * value / 100) + " " + circumference,
      transform: "rotate(-90 60 60)" }));
  }
  const label = svg("text", { x: 60, y: value == null ? 66 : 68, "text-anchor": "middle", "font-size": value == null ? 12 : 26,
    "font-weight": 700, fill: "var(--text)" });
  label.textContent = value == null ? "Not assessed" : value + "%";
  root.appendChild(label);
  container.appendChild(root);
  container.setAttribute("aria-label", value == null ? "Compliance score not assessed" : "Compliance score " + value + " percent");
}

// series: [{name, values:[numbers], cls:"a"|"b"}], labels: x-axis strings
function drawLineChart(container, labels, series) {
  container.replaceChildren();
  if (!labels.length) { container.appendChild(node("p", "muted", "No scans yet.")); return; }
  const W = 560, H = 190, pad = { l: 34, r: 12, t: 12, b: 26 };
  const max = Math.max(1, ...series.flatMap((s) => s.values));
  const x = (i) => pad.l + (labels.length === 1 ? (W - pad.l - pad.r) / 2 : i * (W - pad.l - pad.r) / (labels.length - 1));
  const y = (v) => pad.t + (H - pad.t - pad.b) * (1 - v / max);
  const root = svg("svg", { viewBox: "0 0 " + W + " " + H, role: "presentation" });
  [0, .5, 1].forEach((f) => {
    const gy = pad.t + (H - pad.t - pad.b) * (1 - f);
    root.appendChild(svg("line", { x1: pad.l, x2: W - pad.r, y1: gy, y2: gy, class: "grid" }));
    const t = svg("text", { x: pad.l - 6, y: gy + 4, "text-anchor": "end" });
    t.textContent = Math.round(max * f);
    root.appendChild(t);
  });
  const step = Math.ceil(labels.length / 8);
  labels.forEach((label, i) => {
    if (i % step) return;
    const t = svg("text", { x: x(i), y: H - 8, "text-anchor": "middle" });
    t.textContent = label;
    root.appendChild(t);
  });
  series.forEach((s) => {
    const points = s.values.map((v, i) => x(i) + "," + y(v)).join(" ");
    root.appendChild(svg("polyline", { points, class: "line-" + s.cls }));
    s.values.forEach((v, i) => {
      const dot = svg("circle", { cx: x(i), cy: y(v), r: 3.5, class: "dot-" + s.cls });
      const title = svg("title");
      title.textContent = s.name + ": " + v + " (scan " + labels[i] + ")";
      dot.appendChild(title);
      root.appendChild(dot);
    });
  });
  container.appendChild(root);
  const legend = node("div", "chart-legend");
  series.forEach((s) => {
    const item = node("span");
    const swatch = node("span", "swatch");
    swatch.style.background = s.cls === "a" ? "var(--accent)" : "var(--ok)";
    item.append(swatch, document.createTextNode(s.name));
    legend.appendChild(item);
  });
  container.appendChild(legend);
}

function drawBars(container, entries, classOf) {
  container.replaceChildren();
  if (!entries.length) { container.appendChild(node("p", "muted", "Nothing to show.")); return; }
  const max = Math.max(...entries.map((e) => e[1]), 1);
  entries.forEach(([label, count]) => {
    const row = node("div", "bar-row");
    const track = node("div", "bar-track");
    const fill = node("div", "bar-fill " + (classOf ? classOf(label) : ""));
    fill.style.width = (100 * count / max) + "%";
    track.appendChild(fill);
    row.append(node("span", "bar-label", label), track, node("strong", "bar-count", count));
    container.appendChild(row);
  });
}

// ---------- page chrome ----------
function showLoadError(message) {
  const bar = document.getElementById("data-load-error");
  if (!bar) return;
  bar.textContent = message || "";
  bar.hidden = !message;
}

function start(loader, interval) {
  const run = () => loader().then(() => showLoadError("")).catch((err) => {
    if (err.message !== "Signed out") showLoadError("Failed to load data: " + err.message);
  });
  run();
  if (interval !== 0) setInterval(run, interval || REFRESH_MS);
}

function applyTheme(theme) {
  if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);
}

function initShell() {
  try { applyTheme(localStorage.getItem("pg-theme")); } catch (e) { /* storage can be blocked */ }
  const page = document.body.dataset.page;
  document.querySelectorAll("[data-nav]").forEach((link) => {
    if (link.dataset.nav === page) link.setAttribute("aria-current", "page");
  });
  refreshAccountChip();
  const themeBtn = document.getElementById("theme-btn");
  if (themeBtn) themeBtn.addEventListener("click", () => {
    const explicit = document.documentElement.getAttribute("data-theme");
    const dark = explicit ? explicit === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
    const next = dark ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("pg-theme", next); } catch (e) { /* ignore */ }
  });
  const menuBtn = document.getElementById("menu-btn"), sidebar = document.getElementById("sidebar");
  if (menuBtn && sidebar) menuBtn.addEventListener("click", () => {
    const open = sidebar.classList.toggle("open");
    menuBtn.setAttribute("aria-expanded", String(open));
  });
}

// Account picker: shown only when more than one account has scan data.
async function initViewSwitch() {
  const wrap = document.getElementById("view-switch");
  if (!wrap) return;
  try {
    const view = await getJson("/api/view");
    if (!view.options || view.options.length < 2) return;
    const select = document.getElementById("view-select");
    select.replaceChildren(...view.options.map((o) => {
      const option = node("option", null, o.label);
      option.value = o.id;
      return option;
    }));
    select.value = view.current;
    select.addEventListener("change", async () => {
      select.disabled = true;
      try {
        const csrf = await getCsrf();
        const res = await fetch("/api/view", { method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify({ account_id: select.value }) });
        if (res.ok) window.location.reload();
      } finally { select.disabled = false; }
    });
    wrap.hidden = false;
  } catch (e) { /* the picker is optional */ }
}

if (typeof document.querySelector === "function" && document.body) { initShell(); initViewSwitch(); }
