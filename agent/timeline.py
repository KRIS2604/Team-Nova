"""Build a visual timeline for an incident (R6).

The timeline is the incident's story in time order: every related log entry,
with the ones that raised an alert marked. Repeated events in a row (for
example 4 failed logins) are folded into one line with a count, so the
timeline stays short enough to read at a glance.

Nothing new is stored in the database: the timeline is built from the
incident's alerts and the log entries around them each time it is asked for.
"""

from agent.correlate import gather_context


def describe(entry):
    """One short plain-English line for a log entry."""
    e, user, ip, host = entry["event_type"], entry.get("user"), entry.get("ip"), entry.get("host")
    who = user or ip or host or "unknown"
    frm = " from %s" % ip if ip and user else ""
    if e == "login_failed":
        return "Failed login for %s%s" % (who, frm)
    if e == "login_success":
        return "Successful login for %s%s" % (who, frm)
    if e == "logout":
        return "%s logged out" % who
    if e == "sudo_command":
        return "%s ran a command as admin (sudo)" % who
    if e == "connection_blocked":
        return "Blocked connection from %s" % who
    if e == "connection_allowed":
        return "Allowed connection from %s" % who
    if e == "file_read":
        return "%s read a file on %s%s" % (who, host, frm)
    if e == "process_start":
        return "Process started on %s by %s" % (host, user or "unknown")
    if e.startswith("http_"):
        return "%s got HTTP %s on %s" % (who, e[5:], host)
    return "%s: %s" % (e.replace("_", " "), who)


def _alerts_for_incident(conn, incident_id):
    rows = conn.execute(
        """SELECT a.id, a.log_entry_id, a.timestamp, a.severity, a.reason,
                  l.username, l.ip, l.host
           FROM alerts a JOIN log_entries l ON l.id = a.log_entry_id
           WHERE a.incident_id = ? ORDER BY a.timestamp, a.id""",
        (incident_id,),
    ).fetchall()
    return [{"id": r["id"], "log_entry_id": r["log_entry_id"], "timestamp": r["timestamp"],
             "severity": r["severity"], "reason": r["reason"],
             "user": r["username"], "ip": r["ip"], "host": r["host"]} for r in rows]


def build_timeline(alerts, context):
    """Turn alerts + related log entries into timeline steps, oldest first.

    Each step: {start, end, count, description, source, host, alert}
    where alert is None or {id, severity, reason}.
    """
    by_log = {a["log_entry_id"]: a for a in alerts}
    entries = sorted(context, key=lambda e: (e["timestamp"], e["id"]))

    steps = []
    for e in entries:
        entry = dict(e)
        entry.setdefault("user", entry.get("username"))
        text = describe(entry)
        alert = by_log.get(e["id"])
        last = steps[-1] if steps else None
        # fold repeats: same text, both without an alert
        if last and last["description"] == text and last["alert"] is None and alert is None:
            last["count"] += 1
            last["end"] = e["timestamp"]
            continue
        steps.append({
            "start": e["timestamp"],
            "end": e["timestamp"],
            "count": 1,
            "description": text,
            "source": e["source"],
            "host": e.get("host"),
            "alert": {"id": alert["id"], "severity": alert["severity"], "reason": alert["reason"]} if alert else None,
        })
    return steps


def get_timeline(conn, incident_id):
    """Timeline for one saved incident. Returns [] if the incident has no alerts."""
    alerts = _alerts_for_incident(conn, incident_id)
    if not alerts:
        return []
    context = gather_context(conn, alerts)
    # an alert's own log line must always be on the timeline, even if it has
    # no user or IP to match on
    have = {e["id"] for e in context}
    for a in alerts:
        if a["log_entry_id"] not in have:
            row = conn.execute("SELECT * FROM log_entries WHERE id = ?", (a["log_entry_id"],)).fetchone()
            if row:
                context.append(dict(row))
    return build_timeline(alerts, context)


def format_timeline(steps):
    """Text version for the terminal."""
    lines = []
    for s in steps:
        when = s["start"][11:16]
        if s["end"][11:16] != when:
            when += "-" + s["end"][11:16]
        count = " (x%d)" % s["count"] if s["count"] > 1 else ""
        mark = "  <-- ALERT %s [%s]" % (s["alert"]["id"], s["alert"]["severity"]) if s["alert"] else ""
        lines.append("  %-11s %s%s%s" % (when, s["description"], count, mark))
    return "\n".join(lines)
