"""Load alerts for the agent.

Until the Detection Engine is ready, we use mock alerts from mock_alerts.json.
Each mock alert points at a real log entry (by source + timestamp), so the
agent works on the same data Ingestion saved in the database.
"""

import json
import os

MOCK_FILE = os.path.join(os.path.dirname(__file__), "mock_alerts.json")


def load_mock_alerts(conn, path=MOCK_FILE):
    """Save the mock alerts into the alerts table.

    Returns (added, skipped). Running it twice does not add duplicates.
    An alert is skipped if its log entry is not in the database.
    """
    with open(path, encoding="utf-8-sig") as f:
        mock = json.load(f)

    added, skipped = 0, []
    for a in mock:
        row = conn.execute(
            "SELECT id FROM log_entries WHERE source = ? AND timestamp = ? ORDER BY id LIMIT 1",
            (a["log"]["source"], a["log"]["timestamp"]),
        ).fetchone()
        if row is None:
            skipped.append(a["id"])
            continue
        exists = conn.execute("SELECT 1 FROM alerts WHERE id = ?", (a["id"],)).fetchone()
        if exists:
            continue
        conn.execute(
            """INSERT INTO alerts (id, log_entry_id, incident_id, timestamp, severity, reason, is_false_positive)
               VALUES (?, ?, NULL, ?, ?, ?, NULL)""",
            (a["id"], row["id"], a["log"]["timestamp"], a["severity"], a["reason"]),
        )
        added += 1
    conn.commit()
    return added, skipped


def get_new_alerts(conn):
    """Alerts that are not part of an incident yet, oldest first.

    Each alert also carries its log entry (user, ip, host) so the agent
    can tell which alerts belong together.
    """
    rows = conn.execute(
        """SELECT a.*, l.username, l.ip, l.host, l.source, l.event_type
           FROM alerts a JOIN log_entries l ON l.id = a.log_entry_id
           WHERE a.incident_id IS NULL
           ORDER BY a.timestamp, a.id"""
    ).fetchall()
    return [
        {
            "id": r["id"],
            "log_entry_id": r["log_entry_id"],
            "timestamp": r["timestamp"],
            "severity": r["severity"],
            "reason": r["reason"],
            "user": r["username"],
            "ip": r["ip"],
            "host": r["host"],
            "source": r["source"],
            "event_type": r["event_type"],
        }
        for r in rows
    ]
