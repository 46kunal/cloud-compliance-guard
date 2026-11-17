// Controls register. Values from the API are written with textContent only.
const ctlAdmin = document.body.dataset.role === "admin";

function ctlMessage(text, ok) {
  const box = document.getElementById("ctl-msg");
  box.textContent = text || "";
  box.className = "banner " + (ok ? "banner-ok" : "banner-bad");
  box.hidden = !text;
  if (text) box.scrollIntoView({ block: "center" });
}

async function ctlPost(url, body) {
  const csrf = await getCsrf();
  const res = await fetch(url, { method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body || {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || (url + " returned " + res.status));
  return data;
}

const CTL_PILL = { ATTESTED: ["Attested", "ok"], OVERDUE: ["Review overdue", "bad"], NOT_ATTESTED: ["Not attested", "muted"] };

function controlCard(c) {
  const card = node("article", "fw-card");
  const head = node("div", "fw-card-head");
  const left = node("div");
  left.append(node("h3", null, c.title), node("div", "fw-citation", c.framework + " · " + c.id));
  const tags = node("div", "fw-tags");
  const [label, kind] = CTL_PILL[c.state] || ["Unknown", "muted"];
  tags.append(pill(label, kind), pill("Basis: " + c.verification, c.verification === "primary" ? "ok" : "info"));
  head.append(left, tags);
  card.appendChild(head);
  card.appendChild(node("p", "fw-note", "Basis: " + c.basis));
  card.appendChild(node("p", "fw-note", "Good evidence: " + c.evidence_hint));
  if (c.state !== "NOT_ATTESTED") {
    const lines = ["Owner: " + c.owner, "Evidence: " + c.evidence_note, "Recorded by " + c.attested_by + " on " + formatTime(c.attested_at),
      "Review due: " + formatTime(c.review_due)];
    const box = node("div", "fw-lists");
    lines.forEach((t) => box.appendChild(node("p", "fw-note", t)));
    if (c.evidence_url) {
      const p = node("p", "fw-note");
      const a = node("a", null, c.evidence_url);
      a.href = c.evidence_url; a.target = "_blank"; a.rel = "noopener noreferrer";
      p.append(document.createTextNode("Link: "), a);
      box.appendChild(p);
    }
    card.appendChild(box);
  }
  if (ctlAdmin) {
    const details = node("details", "fw-source");
    details.appendChild(node("summary", null, c.state === "NOT_ATTESTED" ? "Record evidence" : "Update evidence"));
    const form = node("form", "account-form");
    const mk = (labelText, el) => { const l = node("label", "field"); l.append(node("span", null, labelText), el); return l; };
    const owner = node("input"); owner.maxLength = 80; owner.required = true; owner.value = c.owner || "";
    const note = node("input"); note.maxLength = 1000; note.required = true; note.value = c.evidence_note || "";
    const url = node("input"); url.type = "url"; url.value = c.evidence_url || ""; url.placeholder = "https://";
    const days = node("input"); days.type = "number"; days.min = 30; days.max = 400; days.value = 180;
    form.append(mk("Owner (person or team)", owner), mk("What is the evidence?", note), mk("Link (optional)", url), mk("Review again in (days)", days));
    const row = node("div", "full");
    const save = node("button", "btn btn-primary", "Save");
    save.type = "submit";
    row.appendChild(save);
    if (c.state !== "NOT_ATTESTED") {
      const clear = node("button", "btn btn-quiet", "Clear");
      clear.type = "button";
      clear.addEventListener("click", async () => {
        if (!window.confirm("Clear the recorded evidence for this control?")) return;
        try { ctlMessage(""); await ctlPost("/api/controls/" + encodeURIComponent(c.id) + "/revoke"); await loadControls(); } catch (e) { ctlMessage(e.message); }
      });
      row.appendChild(clear);
    }
    form.appendChild(row);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        ctlMessage("");
        await ctlPost("/api/controls/" + encodeURIComponent(c.id) + "/attest",
          { owner: owner.value, evidence_note: note.value, evidence_url: url.value, review_days: days.value });
        await loadControls();
      } catch (e) { ctlMessage(e.message); }
    });
    details.appendChild(form);
    card.appendChild(details);
  }
  return card;
}

async function loadControls() {
  const data = await getJson("/api/controls");
  const groups = {};
  data.controls.forEach((c) => (groups[c.framework] = groups[c.framework] || []).push(c));
  const attested = data.controls.filter((c) => c.state === "ATTESTED").length;
  const overdue = data.controls.filter((c) => c.state === "OVERDUE").length;
  document.getElementById("ctl-summary").replaceChildren(
    node("span", null, attested + " of " + data.controls.length + " attested"), node("span", null, overdue + " overdue"));
  const list = document.getElementById("ctl-list");
  list.replaceChildren();
  Object.entries(groups).forEach(([name, items]) => {
    const group = node("section", "fw-group");
    group.appendChild(node("h2", null, name));
    items.forEach((c) => group.appendChild(controlCard(c)));
    list.appendChild(group);
  });
}

if (document.body.dataset.page === "controls") start(loadControls, 60000);
