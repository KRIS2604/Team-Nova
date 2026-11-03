// Dashboard logic. Uses MOCK_ALERTS and MOCK_INCIDENTS from mock-data.js.

const alerts = MOCK_ALERTS;
const incidents = MOCK_INCIDENTS;

function formatTime(iso) {
  return new Date(iso).toLocaleString();
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
  if (alert.is_false_positive === true) return `<span class="reviewed">False positive</span>`;
  if (alert.is_false_positive === false) return `<span class="reviewed">Confirmed</span>`;
  return `<button data-id="${alert.id}" data-fp="true">False positive</button>` +
         `<button data-id="${alert.id}" data-fp="false">Confirm</button>`;
}

function renderAlerts() {
  const filter = document.getElementById("severity-filter").value;
  const rows = alerts
    .filter(a => filter === "all" || a.severity === filter)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .map(a => `
      <tr>
        <td>${formatTime(a.timestamp)}</td>
        <td>${a.source}</td>
        <td><span class="badge ${a.severity}">${a.severity}</span></td>
        <td>${a.reason}</td>
        <td>${reviewCell(a)}</td>
      </tr>`)
    .join("");
  document.getElementById("alerts-body").innerHTML = rows || `<tr><td colspan="5">No alerts</td></tr>`;
}

function renderIncidents() {
  document.getElementById("incidents-list").innerHTML = incidents
    .map(i => `
      <div class="incident">
        <div class="incident-top" data-toggle="${i.id}">
          <div><span class="incident-title">${i.title}</span><span class="status">${i.status}</span></div>
          <span class="badge ${i.severity}">${i.severity}</span>
        </div>
        <div class="report" id="report-${i.id}">
          <p><b>Summary:</b> ${i.report.summary}</p>
          <p><b>Affected systems:</b> ${i.report.affected_systems.join(", ")}</p>
          <p><b>Recommendation:</b> ${i.report.recommendations}</p>
          <p><b>Created:</b> ${formatTime(i.created_at)}</p>
        </div>
      </div>`)
    .join("");
}

// Mark an alert as false positive or confirmed (only in the page for now, not saved)
document.getElementById("alerts-body").addEventListener("click", e => {
  const id = e.target.dataset.id;
  if (!id) return;
  const alert = alerts.find(a => a.id === id);
  alert.is_false_positive = e.target.dataset.fp === "true";
  renderAlerts();
  renderStats();
});

// Click an incident to show or hide its report
document.getElementById("incidents-list").addEventListener("click", e => {
  const top = e.target.closest("[data-toggle]");
  if (!top) return;
  document.getElementById("report-" + top.dataset.toggle).classList.toggle("open");
});

document.getElementById("severity-filter").addEventListener("change", renderAlerts);

renderStats();
renderAlerts();
renderIncidents();
