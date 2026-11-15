// Frameworks page: one card per obligation, grouped by framework, honest about what is not assessed.
const STATE_PILL = {
  findings_open: ["Findings open", "bad"],
  no_open_findings: ["No open findings", "ok"],
  not_assessed: ["Not assessed", "muted"],
};

function listBlock(title, items) {
  const wrap = node("div");
  wrap.appendChild(node("h4", null, title));
  if (!items.length) {
    wrap.appendChild(node("span", "muted", "None"));
    return wrap;
  }
  const ul = node("ul");
  items.forEach((text) => ul.appendChild(node("li", null, text)));
  wrap.appendChild(ul);
  return wrap;
}

function obligationCard(item) {
  const card = node("article", "fw-card");
  const head = node("div", "fw-card-head");
  const titleBox = node("div");
  titleBox.append(node("h3", null, item.title), node("div", "fw-citation", item.citation));
  const tags = node("div", "fw-tags");
  const [label, kind] = STATE_PILL[item.state] || ["Unknown", "muted"];
  tags.appendChild(pill(item.state === "findings_open" ? item.open_findings + " open" : label, kind));
  if (item.in_force !== "in_force") tags.appendChild(pill("Not yet in force", "warn"));
  tags.appendChild(pill("Verification: " + item.verification, item.verification === "primary" ? "ok" : "info"));
  head.append(titleBox, tags);
  card.appendChild(head);

  const lists = node("div", "fw-lists");
  lists.append(listBlock("Checked automatically", item.automated_checks), listBlock("Not yet automated", item.not_yet_automated));
  card.appendChild(lists);
  if (item.coverage === "manual-only") {
    card.appendChild(node("p", "fw-note", "This duty cannot be assessed from cloud configuration. It needs review by a person."));
  }
  if (item.notes) card.appendChild(node("p", "fw-note", item.notes));
  return card;
}

async function loadFrameworks() {
  const data = await getJson("/api/frameworks");
  document.getElementById("fw-disclaimer").textContent = data.disclaimer;
  const meta = document.getElementById("fw-meta");
  meta.replaceChildren(node("span", null, "Catalog " + data.catalog_version), node("span", null, "Last reviewed " + data.last_reviewed),
    node("span", null, "Active profile: " + data.profile));

  const groups = {};
  data.items.forEach((item) => (groups[item.framework] = groups[item.framework] || []).push(item));
  const container = document.getElementById("framework-groups");
  container.replaceChildren();
  Object.entries(groups).forEach(([name, items]) => {
    const group = node("section", "fw-group");
    group.appendChild(node("h2", null, name));
    items.forEach((item) => group.appendChild(obligationCard(item)));
    container.appendChild(group);
  });
}

if (document.body && document.body.dataset && document.body.dataset.page === "frameworks") start(loadFrameworks, 60000);
