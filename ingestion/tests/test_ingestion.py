"""Tests for the ingestion + database module.

Run from the repo root:
    python -m unittest discover -s ingestion/tests -t . -v

Test IDs (TC-Ixx) match the Sprint 1 test plan.
"""

import os
import sqlite3
import tempfile
import time
import unittest

from ingestion import db
from ingestion.ingest import ingest_file, ingest_path
from ingestion.parsers import ParseError, parse_auth, parse_application

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "sample_logs")


def sample(name):
    return os.path.join(SAMPLES, name)


class IngestionTests(unittest.TestCase):

    def setUp(self):
        self.conn = db.connect(":memory:")  # fresh, empty database for every test

    def tearDown(self):
        self.conn.close()

    def test_TC_I01_schema_creates_tables(self):
        names = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"log_entries", "alerts", "incidents"} <= names)

    def test_TC_I02_auth_logs(self):
        s = ingest_file(self.conn, sample("auth.txt"))
        self.assertEqual(s["loaded"], 11)
        rows = db.get_log_entries(self.conn, source="auth")
        failed = [r for r in rows if r["event_type"] == "login_failed" and r["user"] == "jsmith"]
        self.assertEqual(len(failed), 5)
        self.assertEqual(failed[0]["ip"], "192.168.1.45")
        self.assertEqual(failed[0]["host"], "auth-server-01")

    def test_TC_I03_network_logs(self):
        s = ingest_file(self.conn, sample("network.csv"))
        self.assertEqual(s["loaded"], 11)
        rows = db.get_log_entries(self.conn, source="network")
        blocked = [r for r in rows if r["event_type"] == "connection_blocked"]
        self.assertEqual(len(blocked), 7)
        self.assertTrue(all(r["ip"] == "10.0.0.87" for r in blocked))

    def test_TC_I04_system_logs(self):
        s = ingest_file(self.conn, sample("system.jsonl"))
        self.assertEqual(s["loaded"], 5)
        rows = db.get_log_entries(self.conn, source="system")
        self.assertIn("process_start", [r["event_type"] for r in rows])

    def test_TC_I05_application_logs_converted_to_utc(self):
        line = '10.0.0.14 - mlee [14/Oct/2026:10:05:00 -0500] "GET /reports HTTP/1.1" 200 4096'
        entry = parse_application(line)
        self.assertEqual(entry["timestamp"], "2026-10-14T15:05:00Z")
        self.assertEqual(entry["event_type"], "http_200")
        self.assertEqual(entry["user"], "mlee")

    def test_TC_I06_load_whole_folder(self):
        results = ingest_path(self.conn, SAMPLES)
        self.assertEqual(len(results), 4)
        self.assertEqual(sum(r["loaded"] for r in results), 34)
        self.assertEqual(sum(r["rejected"] for r in results), 7)
        self.assertEqual(db.count_log_entries(self.conn), 34)

    def test_TC_I07_bad_timestamp_rejected_rest_loads(self):
        with self.assertRaises(ParseError) as ctx:
            parse_auth("yesterday auth-server-01 sshd[1]: Failed password for bob from 10.0.0.5 port 1")
        self.assertIn("bad timestamp", str(ctx.exception))
        s = ingest_file(self.conn, sample("auth.txt"))
        self.assertTrue(any("bad timestamp" in e for e in s["errors"]))
        self.assertEqual(s["loaded"], 11)  # good lines still saved

    def test_TC_I08_bad_ip_rejected(self):
        with self.assertRaises(ParseError) as ctx:
            parse_auth("2026-10-14T16:45:13Z auth-server-01 sshd[1]: "
                       "Failed password for bob from 999.10.0.5 port 1")
        self.assertIn("bad IP", str(ctx.exception))

    def test_TC_I09_malformed_json_and_csv_rejected(self):
        sys_s = ingest_file(self.conn, sample("system.jsonl"))
        net_s = ingest_file(self.conn, sample("network.csv"))
        self.assertTrue(any("not valid JSON" in e for e in sys_s["errors"]))
        self.assertTrue(any("missing timestamp" in e for e in sys_s["errors"]))
        self.assertTrue(any("expected 8 columns" in e for e in net_s["errors"]))

    def test_TC_I10_same_file_twice_no_duplicates(self):
        ingest_file(self.conn, sample("auth.txt"))
        second = ingest_file(self.conn, sample("auth.txt"))
        self.assertEqual(second["loaded"], 0)
        self.assertEqual(second["duplicates"], 11)
        self.assertEqual(db.count_log_entries(self.conn), 11)

    def test_TC_I11_query_returns_shared_format(self):
        ingest_path(self.conn, SAMPLES)
        rows = db.get_log_entries(self.conn, since="2026-10-14T14:00:00Z",
                                  until="2026-10-14T14:10:00Z")
        self.assertEqual(len(rows), 6)  # 5 failed + 1 success for jsmith
        self.assertEqual(
            set(rows[0]),
            {"id", "timestamp", "source", "event_type", "user", "ip", "host", "raw_data"})
        times = [r["timestamp"] for r in rows]
        self.assertEqual(times, sorted(times))

    def test_TC_I12_alert_and_incident_rules(self):
        ingest_file(self.conn, sample("auth.txt"))
        log_id = db.get_log_entries(self.conn, limit=1)[0]["id"]
        self.conn.execute(
            "INSERT INTO incidents (id, title, severity, created_at) VALUES (?,?,?,?)",
            ("inc_001", "Possible brute-force login on jsmith", "critical", "2026-10-14T14:08:00Z"))
        self.conn.execute(
            "INSERT INTO alerts (id, log_entry_id, incident_id, timestamp, severity, reason) "
            "VALUES (?,?,?,?,?,?)",
            ("alert_001", log_id, "inc_001", "2026-10-14T14:05:40Z", "high", "5 failed logins"))
        # bad severity is refused
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO alerts (id, log_entry_id, timestamp, severity, reason) "
                "VALUES ('alert_x', ?, '2026-10-14T00:00:00Z', 'urgent', 'x')", (log_id,))
        # alert must point at a real log entry
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO alerts (id, log_entry_id, timestamp, severity, reason) "
                "VALUES ('alert_y', 'log_9999', '2026-10-14T00:00:00Z', 'low', 'x')")
        # analyst feedback: 1 = false positive
        self.conn.execute("UPDATE alerts SET is_false_positive = 1 WHERE id = 'alert_001'")
        fp = self.conn.execute("SELECT is_false_positive FROM alerts").fetchone()[0]
        self.assertEqual(fp, 1)

    def test_TC_I13_unknown_file_type(self):
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
            f.write("hello\n")
        try:
            with self.assertRaises(ValueError) as ctx:
                ingest_file(self.conn, f.name)
            self.assertIn("Can't tell what kind of log", str(ctx.exception))
        finally:
            os.remove(f.name)

    def test_TC_I14_10000_lines_under_5_seconds(self):
        with tempfile.NamedTemporaryFile("w", prefix="auth_big_", suffix=".txt",
                                         delete=False) as f:
            for i in range(10000):
                f.write("2026-10-14T%02d:%02d:%02dZ auth-server-01 sshd[%d]: Failed password "
                        "for user%d from 10.0.%d.%d port 5000 ssh2\n"
                        % (i // 3600 % 24, i // 60 % 60, i % 60, i, i % 50, i % 250, i % 250))
        try:
            start = time.time()
            s = ingest_file(self.conn, f.name)
            took = time.time() - start
        finally:
            os.remove(f.name)
        self.assertEqual(s["read"], 10000)
        self.assertLess(took, 5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
