"""Tests for the Investigation Agent (TC-A01 to TC-A12).

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
from agent.alerts import load_mock_alerts, get_new_alerts
from agent.correlate import group_alerts, highest_severity
from agent.investigate import investigate, get_incidents, main as agent_main
from agent.report import write_report

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "..", "ingestion", "sample_logs")


def alert(i, ts, user=None, ip=None, sev="low"):
    return {"id": "a%d" % i, "timestamp": ts, "user": user, "ip": ip, "host": "h1",
            "severity": sev, "reason": "test", "source": "auth", "event_type": "x"}


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "test.db")
        with contextlib.redirect_stdout(io.StringIO()):
            ingest_main([SAMPLES, "--db", self.db])
        self.conn = connect(self.db)
        os.environ.pop("OPENAI_API_KEY", None)

    def tearDown(self):
        self.conn.close()

    def test_a01_mock_alerts_load(self):
        """TC-A01: all 8 mock alerts load and point at real log entries."""
        added, skipped = load_mock_alerts(self.conn)
        self.assertEqual(added, 8)
        self.assertEqual(skipped, [])
        self.assertEqual(len(get_new_alerts(self.conn)), 8)

    def test_a02_no_duplicate_alerts(self):
        """TC-A02: loading mock alerts twice does not add duplicates."""
        load_mock_alerts(self.conn)
        added, _ = load_mock_alerts(self.conn)
        self.assertEqual(added, 0)

    def test_a03_grouping_same_user_or_ip(self):
        """TC-A03: alerts with the same user or IP within 30 min are one incident."""
        alerts = [alert(1, "2026-10-14T10:00:00Z", user="bob"),
                  alert(2, "2026-10-14T10:10:00Z", user="bob", ip="1.1.1.1"),
                  alert(3, "2026-10-14T10:20:00Z", ip="1.1.1.1"),
                  alert(4, "2026-10-14T10:05:00Z", user="amy")]
        groups = group_alerts(alerts)
        self.assertEqual(sorted(len(g) for g in groups), [1, 3])

    def test_a04_grouping_time_window(self):
        """TC-A04: same user but 2 hours apart stays as two incidents."""
        alerts = [alert(1, "2026-10-14T10:00:00Z", user="bob"),
                  alert(2, "2026-10-14T12:00:00Z", user="bob")]
        self.assertEqual(len(group_alerts(alerts)), 2)

    def test_a05_incidents_from_sample_data(self):
        """TC-A05: 8 mock alerts become 5 incidents; 10.0.0.87 alerts are linked."""
        load_mock_alerts(self.conn)
        created = investigate(self.conn, use_llm=False)
        self.assertEqual(len(created), 5)
        scan = [i for i in created if "10.0.0.87" in i["title"]][0]
        self.assertEqual(scan["alert_ids"], ["alert_003", "alert_004", "alert_005"])
        self.assertEqual(scan["severity"], "high")

    def test_a06_brute_force_report(self):
        """TC-A06: jsmith incident is critical, says brute force, names the host."""
        load_mock_alerts(self.conn)
        inc = [i for i in investigate(self.conn, use_llm=False) if "jsmith" in i["title"]][0]
        self.assertEqual(inc["severity"], "critical")
        self.assertIn("brute-force", inc["title"])
        self.assertIn("5 failed logins", inc["report"]["summary"])
        self.assertEqual(inc["report"]["affected_systems"], ["auth-server-01"])

    def test_a07_saved_in_shared_format(self):
        """TC-A07: incidents are saved and read back in the shared Incident format."""
        load_mock_alerts(self.conn)
        investigate(self.conn, use_llm=False)
        incs = get_incidents(self.conn)
        self.assertEqual(len(incs), 5)
        for inc in incs:
            self.assertEqual(set(inc), {"id", "title", "status", "severity", "created_at", "alert_ids", "report"})
            self.assertEqual(set(inc["report"]), {"summary", "affected_systems", "recommendations"})
        self.assertEqual(investigate(self.conn, use_llm=False), [])  # nothing new the second time

    def test_a08_llm_report_used(self):
        """TC-A08: when an LLM answers, its title/summary are used."""
        fake = lambda a, c: ("LLM title", "LLM summary", "LLM recs")
        rep = write_report([alert(1, "2026-10-14T10:00:00Z", user="bob")], [], llm=fake)
        self.assertEqual(rep["source"], "llm")
        self.assertEqual(rep["title"], "LLM title")

    def test_a09_llm_failure_falls_back(self):
        """TC-A09 (error case): if the LLM fails, the template report is used."""
        def broken(a, c):
            raise ConnectionError("no internet")
        rep = write_report([alert(1, "2026-10-14T10:00:00Z", user="bob")], [], llm=broken)
        self.assertEqual(rep["source"], "template")
        self.assertTrue(rep["summary"])

    def test_a10_empty_database(self):
        """TC-A10 (error case): with no logs loaded, the agent stops with a clear message."""
        empty = os.path.join(self.tmp, "empty.db")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agent_main(["--db", empty, "--mock"]), 1)

    def test_a11_alert_with_missing_log(self):
        """TC-A11 (error case): a mock alert whose log is not in the DB is skipped, not crashed."""
        bad = os.path.join(self.tmp, "bad.json")
        with open(bad, "w") as f:
            json.dump([{"id": "alert_999", "log": {"source": "auth", "timestamp": "2020-01-01T00:00:00Z"},
                        "severity": "low", "reason": "x"}], f)
        added, skipped = load_mock_alerts(self.conn, bad)
        self.assertEqual((added, skipped), (0, ["alert_999"]))

    def test_a12_highest_severity(self):
        """TC-A12: incident severity is the highest of its alerts."""
        self.assertEqual(highest_severity([alert(1, "x", sev="low"), alert(2, "x", sev="critical"),
                                           alert(3, "x", sev="medium")]), "critical")


if __name__ == "__main__":
    unittest.main()
