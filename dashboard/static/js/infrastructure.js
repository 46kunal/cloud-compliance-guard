// Infrastructure page: which server answered, Auto Scaling group state, and the scanner cost estimate.
function table(headers, rows) {
  const wrap = node("div", "table-wrap");
  const t = document.createElement("table");
  const head = document.createElement("tr");
  headers.forEach((h) => head.appendChild(node("th", null, h)));
  const thead = document.createElement("thead");
  thead.appendChild(head);
  const tbody = document.createElement("tbody");
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    row.forEach((value) => tr.appendChild(cell(value)));
    tbody.appendChild(tr);
  });
  t.append(thead, tbody);
  wrap.appendChild(t);
  return wrap;
}

function renderAutoscaling(asg) {
  const body = document.getElementById("asg-body");
  body.replaceChildren();
  if (!asg) {
    document.getElementById("asg-summary").textContent = "";
    body.appendChild(node("p", "muted", "Not running under an Auto Scaling group (local or single-server mode)."));
    return;
  }
  if (asg.error) { body.appendChild(node("p", "bad", asg.error)); return; }
  document.getElementById("asg-summary").textContent =
    asg.name + " · desired " + asg.desired + " (min " + asg.min + ", max " + asg.max + ")";
  body.appendChild(table(["Instance", "Zone", "State", "Health"], asg.instances.map((i) => [i.id, i.zone, i.state, i.health])));
  if (asg.recent_activities.length) {
    body.appendChild(node("h3", null, "Recent scaling activity"));
    body.appendChild(table(["Started", "Status", "What happened"],
      asg.recent_activities.map((a) => [formatTime(a.started), a.status, a.cause || a.description])));
  }
}

function renderCost(cost) {
  const body = document.getElementById("cost-body");
  body.replaceChildren();
  if (!cost.available) { body.appendChild(node("p", "muted", cost.reason)); return; }
  document.getElementById("cost-label").textContent = cost.label;
  const usd = (n) => "$" + Number(n).toFixed(n < 1 ? 4 : 2);
  body.appendChild(table(["Scanner design", "Estimated monthly cost"], [
    ["Scheduled Lambda (every " + cost.scan_interval_minutes + " min, " + cost.avg_scan_seconds + " s per scan, " + cost.runs_per_month + " runs)", usd(cost.serverless_scanner_usd_per_month)],
    ["Always-on t3.micro instance running the same scanner", usd(cost.always_on_instance_usd_per_month)]]));
  body.appendChild(node("p", "hint", (cost.saving_percent >= 99 ? "Over 99%" : "About " + cost.saving_percent + "%") + " lower for the serverless scanner under these assumptions. Rates are illustrative list prices; check the AWS Pricing Calculator for your region."));
}

async function loadInfrastructure() {
  const usage = await getJson("/api/usage");
  const instance = usage.instance;
  document.getElementById("inf-instance").textContent = instance.instance_id;
  document.getElementById("inf-zone").textContent =
    [instance.availability_zone, instance.instance_type, instance.on_ec2 ? "EC2" : "not on EC2"].filter(Boolean).join(" · ");
  document.getElementById("inf-storage").textContent = usage.storage_backend === "dynamodb" ? "DynamoDB" : "SQLite (local)";
  const me = await getJson("/api/instance");
  document.getElementById("inf-profile").textContent = me.profile === "india" ? "India" : "Baseline";
  document.getElementById("inf-auth").textContent = "Login mode: " + me.auth_mode;
  document.getElementById("inf-scans").textContent = usage.scans_recorded;
  document.getElementById("inf-avg").textContent = usage.cost.available ? "Average " + usage.cost.avg_scan_seconds + " s per scan" : "";
  renderAutoscaling(usage.autoscaling);
  renderCost(usage.cost);
}

if (document.body && document.body.dataset && document.body.dataset.page === "infrastructure") start(loadInfrastructure, 30000);
