"""Tests for the incident timeline, R6 (TC-A13 to TC-A19).

Run from the repo root:
    python -m unittest discover -s agent/tests -t . -v
"""

import contextlib
import io
import json
import os
import tempfile
import unittest

from ingestion.db import connect
from ingestion.ingest import main as ingest_main
from agent.alerts import load_mock_alerts
from agent.investigate import investigate, main as agent_main
from agent.timeline import build_timeline, get_timeline, format_timeline

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "..", "ingestion", "sample_logs")


class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "test.db")
        with contextlib.redirect_stdout(io.StringIO()):
            ingest_main([SAMPLES, "--db", self.db])
        self.conn = connect(self.db)
        os.environ.pop("OPENAI_API_KEY", None)
        load_mock_alerts(self.conn)
        self.incidents = {i["title"]: i for i in investigate(self.conn, use_llm=False)}

    def tearDown(self):
        self.conn.close()

    def _incident(self, words):
        return [i for t, i in self.incidents.items() if words in t][0]

    def test_a13_brute_force_timeline(self):
        """TC-A13: jsmith timeline = 4 failed logins folded, then 2 alert steps, in time order."""
        steps = get_timeline(self.conn, self._incident("jsmith")["id"])
        self.assertEqual(len(steps), 3)
        self.assertEqual(steps[0]["count"], 4)
        self.assertIsNone(steps[0]["alert"])
        self.assertEqual(steps[1]["alert"]["id"], "alert_001")
        self.assertIn("Successful login", steps[2]["description"])
        self.assertEqual(steps[2]["alert"]["severity"], "critical")
        starts = [s["start"] for s in steps]
        self.assertEqual(starts, sorted(starts))

    def test_a14_every_alert_on_timeline(self):
        """TC-A14: every alert of every incident appears on its timeline exactly once."""
        for inc in self.incidents.values():
            marked = [s["alert"]["id"] for s in get_timeline(self.conn, inc["id"]) if s["alert"]]
            self.assertEqual(sorted(marked), sorted(inc["alert_ids"]))

    def test_a15_scan_then_theft_story(self):
        """TC-A15: 10.0.0.87 timeline shows blocked scan, then file read, then outbound connection."""
        steps = get_timeline(self.conn, self._incident("10.0.0.87")["id"])
        text = " | ".join(s["description"] for s in steps)
        self.assertLess(text.index("Blocked connection"), text.index("read a file"))
        self.assertLess(text.index("read a file"), text.index("Allowed connection"))

    def test_a16_alert_without_user_or_ip(self):
        """TC-A16 (error case): an alert whose log has no user or IP still shows on its timeline."""
        log_id = self.conn.execute(
            "SELECT id FROM log_entries WHERE event_type = 'disk_warning'").fetchone()[0]
        self.conn.execute("INSERT INTO alerts (id, log_entry_id, incident_id, timestamp, severity, reason) "
                          "VALUES ('alert_900', ?, NULL, '2026-10-14T06:00:00Z', 'low', 'disk almost full')", (log_id,))
        self.conn.commit()
        inc = investigate(self.conn, use_llm=False)[0]
        steps = get_timeline(self.conn, inc["id"])
        self.assertEqual([s["alert"]["id"] for s in steps if s["alert"]], ["alert_900"])

    def test_a17_unknown_incident(self):
        """TC-A17 (error case): asking for an incident that doesn't exist gives a clear message."""
        self.assertEqual(get_timeline(self.conn, "inc_999"), [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = agent_main(["--db", self.db, "--timeline", "inc_999"])
        self.assertEqual(code, 1)
        self.assertIn("No incident called inc_999", out.getvalue())

    def test_a18_export_includes_timeline(self):
        """TC-A18: --export writes each incident with its timeline for the dashboard."""
        path = os.path.join(self.tmp, "incidents.json")
        with contextlib.redirect_stdout(io.StringIO()):
            agent_main(["--db", self.db, "--export", path])
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data), 5)
        for inc in data:
            self.assertTrue(inc["timeline"])
            self.assertEqual(set(inc["timeline"][0]),
                             {"start", "end", "count", "description", "source", "host", "alert"})

    def test_a19_text_format(self):
        """TC-A19: terminal view shows times, repeat counts and ALERT markers."""
        steps = build_timeline(
            [{"id": "a1", "log_entry_id": "l3", "severity": "high", "reason": "r"}],
            [{"id": "l1", "timestamp": "2026-10-14T10:00:00Z", "source": "auth", "event_type": "login_failed",
              "user": "bob", "ip": "1.1.1.1", "host": "h"},
             {"id": "l2", "timestamp": "2026-10-14T10:01:00Z", "source": "auth", "event_type": "login_failed",
              "user": "bob", "ip": "1.1.1.1", "host": "h"},
             {"id": "l3", "timestamp": "2026-10-14T10:02:00Z", "source": "auth", "event_type": "login_success",
              "user": "bob", "ip": "1.1.1.1", "host": "h"}])
        text = format_timeline(steps)
        self.assertIn("10:00-10:01", text)
        self.assertIn("(x2)", text)
        self.assertIn("ALERT a1 [high]", text)


if __name__ == "__main__":
    unittest.main()
