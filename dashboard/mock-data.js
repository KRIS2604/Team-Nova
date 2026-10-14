// Mock data for the dashboard until the real pipeline is connected.
// Format may change once the team finalizes LogEntry / Alert / Incident.

const MOCK_ALERTS = [
  { id: "alert_001", incident_id: "inc_001", timestamp: "2026-10-14T14:05:40Z", source: "auth", severity: "high", reason: "5 failed logins in 2 minutes for user jsmith", is_false_positive: null },
  { id: "alert_002", incident_id: "inc_001", timestamp: "2026-10-14T14:07:12Z", source: "auth", severity: "critical", reason: "Successful login for jsmith right after failed attempts", is_false_positive: null },
  { id: "alert_003", incident_id: "inc_002", timestamp: "2026-10-14T11:22:05Z", source: "network", severity: "medium", reason: "Port scan detected from 10.0.0.87", is_false_positive: null },
  { id: "alert_004", incident_id: "inc_003", timestamp: "2026-10-13T22:41:50Z", source: "system", severity: "low", reason: "Unusual process started on web-server-02", is_false_positive: true },
  { id: "alert_005", incident_id: "inc_002", timestamp: "2026-10-14T11:25:33Z", source: "network", severity: "high", reason: "Large outbound transfer to unknown IP", is_false_positive: null },
  { id: "alert_006", incident_id: "inc_004", timestamp: "2026-10-12T09:15:00Z", source: "application", severity: "medium", reason: "Repeated 403 errors on admin page", is_false_positive: false }
];

const MOCK_INCIDENTS = [
  { id: "inc_001", title: "Possible brute-force login on jsmith", status: "open", severity: "critical", created_at: "2026-10-14T14:08:00Z",
    report: { summary: "Several failed logins were followed by a successful login from the same IP. This may be a guessed password.", affected_systems: ["auth-server-01"], recommendations: "Reset jsmith's password and block IP 192.168.1.45." } },
  { id: "inc_002", title: "Suspicious network activity from 10.0.0.87", status: "investigating", severity: "high", created_at: "2026-10-14T11:26:00Z",
    report: { summary: "A port scan was followed by a large outbound data transfer from the same host.", affected_systems: ["10.0.0.87", "file-server-01"], recommendations: "Isolate 10.0.0.87 and check what data was sent." } },
  { id: "inc_003", title: "Unusual process on web-server-02", status: "resolved", severity: "low", created_at: "2026-10-13T22:45:00Z",
    report: { summary: "The process was a scheduled backup job. Marked as false positive.", affected_systems: ["web-server-02"], recommendations: "No action needed." } },
  { id: "inc_004", title: "Repeated access attempts on admin page", status: "resolved", severity: "medium", created_at: "2026-10-12T09:20:00Z",
    report: { summary: "One user kept trying to open the admin page without permission.", affected_systems: ["app-server-01"], recommendations: "Remind the user about access rules." } }
];
