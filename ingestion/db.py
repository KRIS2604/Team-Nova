"""Database helpers for Team Nova (SQLite for Sprint 1).

Other modules can use these functions instead of writing SQL:
    from ingestion.db import connect, get_log_entries
"""

import os
import sqlite3
from datetime import datetime, timezone

SCHEMA_FILE = os.path.join(os.path.dirname(__file__), "schema.sql")
DEFAULT_DB = os.environ.get("TEAMNOVA_DB", "teamnova.db")


def connect(path=DEFAULT_DB):
    """Open the database and make sure the tables exist."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    return conn


def init_db(conn):
    with open(SCHEMA_FILE, encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()


def _next_log_id(conn):
    row = conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()
    return "log_%04d" % (row[0] + 1)


def insert_log_entry(conn, entry):
    """Save one clean LogEntry dict.

    Returns "inserted" or "duplicate" (same source, timestamp and raw line).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        conn.execute(
            """INSERT INTO log_entries
               (id, timestamp, source, event_type, username, ip, host, raw_data, ingested_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _next_log_id(conn),
                entry["timestamp"],
                entry["source"],
                entry["event_type"],
                entry.get("user"),
                entry.get("ip"),
                entry.get("host"),
                entry["raw_data"],
                now,
            ),
        )
        return "inserted"
    except sqlite3.IntegrityError as e:
        if "UNIQUE" in str(e):
            return "duplicate"
        raise


def row_to_dict(row):
    """Turn a log_entries row into the shared LogEntry format."""
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "source": row["source"],
        "event_type": row["event_type"],
        "user": row["username"],
        "ip": row["ip"],
        "host": row["host"],
        "raw_data": row["raw_data"],
    }


def get_log_entries(conn, source=None, since=None, until=None, limit=None):
    """Get log entries, oldest first. All filters are optional.

    since / until are ISO timestamps like "2026-10-14T14:00:00Z".
    """
    sql = "SELECT * FROM log_entries WHERE 1=1"
    params = []
    if source:
        sql += " AND source = ?"
        params.append(source)
    if since:
        sql += " AND timestamp >= ?"
        params.append(since)
    if until:
        sql += " AND timestamp <= ?"
        params.append(until)
    sql += " ORDER BY timestamp, id"
    if limit:
        sql += " LIMIT ?"
        params.append(int(limit))
    return [row_to_dict(r) for r in conn.execute(sql, params)]


def count_log_entries(conn):
    return conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
