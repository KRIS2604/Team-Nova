// Dashboard logic. Gets real data from the backend API (dashboard/server.py).
// Start the server with:  python -m dashboard.server   then open http://localhost:8000

let alerts = [];
let incidents = [];

// Text from the logs goes into the page, so escape it first.
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Logs and reports use UTC, so the page shows UTC too.
function formatTime(iso) {
  return iso ? iso.replace("T", " ").replace("Z", "") + " UTC" : "-";
}

function shortTime(iso) {
  return iso ? iso.slice(11, 19) : "";
}

function showMessage(text) {
  const box = document.getElementById("message");
  box.textContent = text || "";
  box.hidden = !text;
}

async function api(path, options) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed (" + res.status + ")");
  return data;
}

async function loadData() {
  try {
    [alerts, incidents] = await Promise.all([api("/api/alerts"), api("/api/incidents")]);
    showMessage("");
  } catch (err) {
    showMessage("Could not load data from the server. Start it with: python -m dashboard.server");
    return;
  }
  renderStats();
  renderAlerts();
  renderIncidents();
}

function renderStats() {
  const openIncidents = incidents.filter(i => i.status !== "resolved").length;
  const critical = alerts.filter(a => a.severity === "critical").length;
  const falsePositives = alerts.filter(a => a.is_false_positive === true).length;
  const stats = [
    { num: alerts.length, label: "Total alerts" },
    { num: critical, label: "Critical alerts" },
    { num: openIncidents, label: "Open incidents" },
    { num: falsePositives, label: "Marked false positive" }
  ];
  document.getElementById("stats").innerHTML = stats
    .map(s => `<div class="stat"><div class="num">${s.num}</div><div class="label">${s.label}</div></div>`)
    .join("");
}

function reviewCell(alert) {
  if (alert.is_false_positive === true)
    return `<span class="reviewed">False positive</span> <button data-id="${esc(alert.id)}" data-fp="null">Undo</button>`;
  if (alert.is_false_positive === false)
    return `<span class="reviewed">Confirmed</span> <button data-id="${esc(alert.id)}" data-fp="null">Undo</button>`;
  return `<button data-id="${esc(alert.id)}" data-fp="true">False positive</button>` +
         `<button data-id="${esc(alert.id)}" data-fp="false">Confirm</button>`;
}

function renderAlerts() {
  const filter = document.getElementById("severity-filter").value;
  const rows = alerts
    .filter(a => filter === "all" || a.severity === filter)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .map(a => `
      <tr>
        <td>${formatTime(a.timestamp)}</td>
        <td>${esc(a.source)}</td>
        <td><span class="badge ${esc(a.severity)}">${esc(a.severity)}</span></td>
        <td>${esc(a.reason)}</td>
        <td>${esc(a.incident_id || "-")}</td>
        <td>${reviewCell(a)}</td>
      </tr>`)
    .join("");
  document.getElementById("alerts-body").innerHTML = rows || `<tr><td colspan="6">No alerts</td></tr>`;
}

function renderTimeline(steps) {
  if (!steps || !steps.length) return `<p class="muted">No timeline for this incident.</p>`;
  return `<ol class="timeline">` + steps.map(s => {
    let when = shortTime(s.start);
    if (s.end !== s.start) when += " - " + shortTime(s.end);
    const count = s.count > 1 ? ` <span class="count">x${s.count}</span>` : "";
    const alert = s.alert
      ? `<div class="tl-alert"><span class="badge ${esc(s.alert.severity)}">${esc(s.alert.severity)}</span> ${esc(s.alert.id)}: ${esc(s.alert.reason)}</div>`
      : "";
    return `<li class="${s.alert ? "has-alert" : ""}">
        <span class="tl-time">${when}</span>
        <span class="tl-text">${esc(s.description)}${count} <span class="muted">(${esc(s.source)}, ${esc(s.host || "-")})</span></span>
        ${alert}
      </li>`;
  }).join("") + `</ol>`;
}

function renderIncidents() {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const list = [...incidents].sort((a, b) => order[a.severity] - order[b.severity]);
  document.getElementById("incidents-list").innerHTML = list
    .map(i => `
      <div class="incident">
        <div class="incident-top" data-toggle="${esc(i.id)}">
          <div><span class="incident-id">${esc(i.id)}</span><span class="incident-title">${esc(i.title)}</span><span class="status">${esc(i.status)}</span></div>
          <span class="badge ${esc(i.severity)}">${esc(i.severity)}</span>
        </div>
        <div class="report" id="report-${esc(i.id)}">
          <p><b>Summary:</b> ${esc(i.report.summary)}</p>
          <p><b>Affected systems:</b> ${esc(i.report.affected_systems.join(", "))}</p>
          <p><b>Recommendation:</b> ${esc(i.report.recommendations)}</p>
          <p><b>Alerts:</b> ${esc(i.alert_ids.join(", "))}</p>
          <p><b>Created:</b> ${formatTime(i.created_at)}</p>
          <h3>Timeline</h3>
          ${renderTimeline(i.timeline)}
        </div>
      </div>`)
    .join("") || `<p class="muted">No incidents yet.</p>`;
}

// Mark an alert as false positive / confirmed, or undo. Saved in the database (R8).
document.getElementById("alerts-body").addEventListener("click", async e => {
  const id = e.target.dataset.id;
  if (!id) return;
  const value = JSON.parse(e.target.dataset.fp); // true, false or null
  e.target.disabled = true;
  try {
    const updated = await api(`/api/alerts/${encodeURIComponent(id)}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ is_false_positive: value })
    });
    alerts = alerts.map(a => (a.id === id ? updated : a));
    showMessage("");
  } catch (err) {
    showMessage("Could not save feedback: " + err.message);
  }
  renderAlerts();
  renderStats();
});

// Click an incident to show or hide its report and timeline
document.getElementById("incidents-list").addEventListener("click", e => {
  const top = e.target.closest("[data-toggle]");
  if (!top) return;
  document.getElementById("report-" + top.dataset.toggle).classList.toggle("open");
});

document.getElementById("severity-filter").addEventListener("change", renderAlerts);
document.getElementById("refresh").addEventListener("click", loadData);

loadData();
