"""Tests for the dashboard web app and API (TC-D11 to TC-D17).

Run from the repo root:
    python -m unittest discover -s dashboard/tests -t . -v
Each test class starts the server on a free port with a temporary database.
"""

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from dashboard.server import make_server, setup_data


class ServerTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.tmp, "test.db")
        cls.summary = setup_data(cls.db_path, use_llm=False)
        cls.server = make_server(cls.db_path, "127.0.0.1", 0, quiet=True)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def request(self, path, method="GET", body=None):
        """Returns (status, parsed JSON or raw text)."""
        data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as res:
                status, raw, ctype = res.status, res.read(), res.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            status, raw, ctype = e.code, e.read(), e.headers.get("Content-Type", "")
        return status, (json.loads(raw) if "json" in ctype else raw.decode())

    # TC-D11: pipeline runs on start and the incidents API returns real data
    def test_incidents_api(self):
        self.assertEqual(self.summary["incidents_created"], 5)
        status, incidents = self.request("/api/incidents")
        self.assertEqual(status, 200)
        self.assertEqual(len(incidents), 5)
        for inc in incidents:
            for key in ("id", "title", "status", "severity", "created_at", "alert_ids", "report", "timeline"):
                self.assertIn(key, inc)
        brute = [i for i in incidents if "brute-force" in i["title"]][0]
        self.assertEqual(brute["severity"], "critical")
        self.assertEqual(brute["alert_ids"], ["alert_001", "alert_002"])

    # TC-D12: alerts API uses the shared format and links to incidents and logs
    def test_alerts_api(self):
        status, alerts = self.request("/api/alerts")
        self.assertEqual(status, 200)
        self.assertEqual(len(alerts), 8)
        for a in alerts:
            self.assertTrue(a["log_entry_id"].startswith("log_"))
            self.assertTrue(a["incident_id"].startswith("inc_"))
            self.assertIn(a["is_false_positive"], (True, False, None))
        times = [a["timestamp"] for a in alerts]
        self.assertEqual(times, sorted(times, reverse=True))  # newest first

    # TC-D13: analyst feedback is saved and still there on the next request (fixes TC-D06)
    def test_feedback_is_saved(self):
        status, alert = self.request("/api/alerts/alert_006/feedback", "POST", {"is_false_positive": True})
        self.assertEqual(status, 200)
        self.assertIs(alert["is_false_positive"], True)
        _, alerts = self.request("/api/alerts")
        self.assertIs([a for a in alerts if a["id"] == "alert_006"][0]["is_false_positive"], True)
        # undo
        status, alert = self.request("/api/alerts/alert_006/feedback", "POST", {"is_false_positive": None})
        self.assertEqual(status, 200)
        self.assertIsNone(alert["is_false_positive"])

    # TC-D14: bad requests get a clear error, not a crash
    def test_error_cases(self):
        status, body = self.request("/api/alerts/alert_999/feedback", "POST", {"is_false_positive": True})
        self.assertEqual(status, 404)
        self.assertIn("alert_999", body["error"])
        status, body = self.request("/api/alerts/alert_001/feedback", "POST", b"not json")
        self.assertEqual(status, 400)
        status, body = self.request("/api/alerts/alert_001/feedback", "POST", {"is_false_positive": "yes"})
        self.assertEqual(status, 400)
        status, body = self.request("/api/incidents/inc_999")
        self.assertEqual(status, 404)
        status, body = self.request("/api/nothing")
        self.assertEqual(status, 404)
        # server still works after the errors
        status, _ = self.request("/api/health")
        self.assertEqual(status, 200)

    # TC-D15: one incident with its timeline (R6)
    def test_single_incident_timeline(self):
        _, incidents = self.request("/api/incidents")
        brute_id = [i for i in incidents if "brute-force" in i["title"]][0]["id"]
        status, inc = self.request("/api/incidents/" + brute_id)
        self.assertEqual(status, 200)
        flagged = [s for s in inc["timeline"] if s["alert"]]
        self.assertEqual([s["alert"]["id"] for s in flagged], ["alert_001", "alert_002"])

    # TC-D16: the dashboard page and its files are served; other files are not
    def test_static_files(self):
        status, html = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("Team Nova Analyst Dashboard", html)
        self.assertEqual(self.request("/app.js")[0], 200)
        self.assertEqual(self.request("/style.css")[0], 200)
        self.assertEqual(self.request("/server.py")[0], 404)
        self.assertEqual(self.request("/../ingestion/db.py")[0], 404)

    # TC-D17: running setup again does not duplicate logs, alerts or incidents
    def test_setup_twice_no_duplicates(self):
        again = setup_data(self.db_path, use_llm=False)
        self.assertEqual(again, {"logs_loaded": 0, "alerts_added": 0, "incidents_created": 0})
        _, health = self.request("/api/health")
        self.assertEqual((health["log_entries"], health["alerts"], health["incidents"]), (34, 8, 5))


if __name__ == "__main__":
    unittest.main()
