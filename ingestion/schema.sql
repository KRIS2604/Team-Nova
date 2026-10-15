-- Team Nova database schema (Sprint 1)
-- Tables: log_entries, incidents, alerts
-- Written for SQLite in Sprint 1. Kept close to standard SQL so it can move
-- to PostgreSQL in Sprint 2 with small changes.
-- Note: the column is "username", not "user", because "user" is a reserved
-- word in PostgreSQL. The shared JSON format still calls the field "user".

CREATE TABLE IF NOT EXISTS log_entries (
    id          TEXT PRIMARY KEY,                 -- e.g. log_0001
    timestamp   TEXT NOT NULL,                    -- UTC, ISO 8601: 2026-10-14T14:05:40Z
    source      TEXT NOT NULL
                CHECK (source IN ('auth', 'network', 'system', 'application')),
    event_type  TEXT NOT NULL,                    -- e.g. login_failed, connection_blocked
    username    TEXT,                             -- can be empty (network logs)
    ip          TEXT,                             -- source IP, can be empty
    host        TEXT,                             -- machine that wrote the log
    raw_data    TEXT NOT NULL,                    -- the original log line, unchanged
    ingested_at TEXT NOT NULL,
    UNIQUE (source, timestamp, raw_data)          -- stops the same line loading twice
);

CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries (timestamp);
CREATE INDEX IF NOT EXISTS idx_log_entries_source    ON log_entries (source);
CREATE INDEX IF NOT EXISTS idx_log_entries_ip        ON log_entries (ip);

CREATE TABLE IF NOT EXISTS incidents (
    id                      TEXT PRIMARY KEY,     -- e.g. inc_001
    title                   TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open', 'investigating', 'resolved')),
    severity                TEXT NOT NULL
                            CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    created_at              TEXT NOT NULL,
    report_summary          TEXT,                 -- filled in by the Investigation Agent
    report_affected_systems TEXT,                 -- JSON list, e.g. ["auth-server-01"]
    report_recommendations  TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id                TEXT PRIMARY KEY,           -- e.g. alert_001
    log_entry_id      TEXT NOT NULL REFERENCES log_entries (id),
    incident_id       TEXT REFERENCES incidents (id),   -- empty until grouped
    timestamp         TEXT NOT NULL,
    severity          TEXT NOT NULL
                      CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    reason            TEXT NOT NULL,
    is_false_positive INTEGER                     -- NULL = not reviewed, 1 = false positive, 0 = confirmed
                      CHECK (is_false_positive IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts (incident_id);
