const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

class Element {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.attributes = {};
    this.listeners = {};
    this.textContent = "";
    this.className = "";
  }
  appendChild(child) { child.parent = this; this.children.push(child); return child; }
  append(...children) { children.forEach((child) => this.appendChild(child)); }
  replaceChildren(...children) { this.children = []; this.textContent = ""; this.append(...children); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  async dispatch(name) { return this.listeners[name]?.({ target: this }); }
  after(element) {
    const siblings = this.parent.children;
    const index = siblings.indexOf(this);
    element.parent = this.parent;
    siblings.splice(index + 1, 0, element);
  }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this);
  }
  get childElementCount() { return this.children.length; }
  get firstElementChild() { return this.children[0] || null; }
}

const tbody = new Element("tbody");
const document = {
  createElement: (tag) => new Element(tag),
  getElementById: (id) => id === "violations-body" ? tbody : null,
};
let evidenceRequests = 0;
const evidenceResponse = {
  finding_id: 41,
  evidence: [{
    evidence_id: 5, finding_id: 41, scan_id: 9, scan_status: "PARTIAL",
    resource_id: "bucket <script>alert(1)</script>", resource_type: "object_storage", service: "s3",
    rule: "public_storage", severity: "HIGH", lifecycle_status: "NEW",
    observed_configuration: { is_public: true }, expected_condition: false,
    explanation: "Public access was observed.", compliance_mapping: "Not mapped",
    detected_at: "2026-11-13T01:00:00Z", evidence_source: "s3",
    rule_reference: "public_storage", collection_status: "COLLECTED",
    recommended_action: "Restrict access",
  }],
};
const context = vm.createContext({
  document,
  window: { PAGE: "none" },
  setInterval: () => 0,
  fetch: async (url) => {
    evidenceRequests += 1;
    assert.equal(url, "/api/findings/41/evidence");
    return { ok: true, json: async () => evidenceResponse };
  },
});
vm.runInContext(fs.readFileSync("dashboard/static/js/common.js", "utf8"), context);
vm.runInContext(fs.readFileSync("dashboard/static/js/findings.js", "utf8"), context);
vm.runInContext(`currentViolations = [{id: 41, evidence_available: true, status: "NEW", severity: "HIGH", rule: "public_storage",
  resource_id: "bucket", remediation: {}}]; renderViolations();`, context);

function findByClass(node, className) {
  if (node.className === className) return node;
  for (const child of node.children) {
    const found = findByClass(child, className);
    if (found) return found;
  }
  return null;
}
function allText(node) {
  return node.textContent + node.children.map(allText).join("");
}

(async () => {
  const button = findByClass(tbody, "evidence-toggle");
  assert.ok(button, "finding row exposes evidence control");
  assert.equal(button.getAttribute("aria-expanded"), "false");
  await button.dispatch("click");
  assert.equal(button.getAttribute("aria-expanded"), "true");
  assert.equal(tbody.children.length, 2, "detail row expands below its own finding");
  assert.match(allText(tbody), /bucket <script>alert\(1\)<\/script>/);
  assert.match(allText(tbody), /Public access was observed/);
  assert.match(allText(tbody), /PARTIAL/);
  assert.equal(findByClass(tbody, "evidence-panel").innerHTML, undefined, "untrusted values are rendered as text");
  await button.dispatch("click");
  assert.equal(tbody.children.length, 1, "detail row collapses");
  assert.equal(button.getAttribute("aria-expanded"), "false");
  await button.dispatch("click");
  assert.equal(evidenceRequests, 1, "expanded evidence is reused for the same finding");
  const emptyPanel = new Element("div");
  context.__emptyPanel = emptyPanel;
  vm.runInContext("renderEvidence(__emptyPanel, [])", context);
  assert.equal(emptyPanel.textContent, "Evidence not available for this finding.");
  vm.runInContext(`currentViolations = [{id: 42, evidence_available: false, status: "ACTIVE", severity: "LOW",
    rule: "mfa_required", resource_id: "user", remediation: {}}]; renderViolations();`, context);
  assert.match(allText(tbody), /No evidence available/);
  assert.equal(findByClass(tbody, "evidence-toggle"), null, "findings without evidence do not show a dead button");
  console.log("Evidence row expanded/collapsed and rendered safely.");
})().catch((error) => { console.error(error); process.exitCode = 1; });
