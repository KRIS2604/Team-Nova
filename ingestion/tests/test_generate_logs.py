"""Tests for the simulated log generator.

Run from the repo root:
    python -m unittest discover -s ingestion/tests -t . -v

Test IDs (TC-I16 to TC-I20) are new in Sprint 2.
"""

import io
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout

from ingestion import db
from ingestion.generate_logs import BRUTE_FORCE, FILE_NAMES, generate, main
from ingestion.ingest import ingest_path


class GenerateLogsTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def folder(self, name="logs"):
        return os.path.join(self.tmp, name)

    def read_all(self, folder):
        out = {}
        for name in sorted(os.listdir(folder)):
            with open(os.path.join(folder, name), encoding="utf-8") as f:
                out[name] = f.read()
        return out

    def test_TC_I16_creates_four_files(self):
        generate(self.folder(), lines=200, seed=1)
        self.assertEqual(sorted(os.listdir(self.folder())), sorted(FILE_NAMES.values()))

    def test_TC_I17_every_line_loads(self):
        summary = generate(self.folder(), lines=2000, seed=42)
        conn = db.connect(":memory:")
        results = ingest_path(conn, self.folder())
        conn.close()
        self.assertEqual(len(results), 4)
        self.assertEqual(sum(r["rejected"] for r in results), 0)
        self.assertEqual(sum(r["duplicates"] for r in results), 0)
        self.assertEqual(sum(r["loaded"] for r in results), sum(summary["files"].values()))

    def test_TC_I18_same_seed_same_output(self):
        generate(self.folder("a"), lines=500, seed=7)
        generate(self.folder("b"), lines=500, seed=7)
        generate(self.folder("c"), lines=500, seed=8)
        self.assertEqual(self.read_all(self.folder("a")), self.read_all(self.folder("b")))
        self.assertNotEqual(self.read_all(self.folder("a")), self.read_all(self.folder("c")))

    def test_TC_I19_brute_force_is_planted(self):
        generate(self.folder(), lines=500, seed=42)
        conn = db.connect(":memory:")
        ingest_path(conn, self.folder())
        rows = db.get_log_entries(conn, source="auth")
        conn.close()
        mine = [r for r in rows if r["user"] == BRUTE_FORCE["user"] and r["ip"] == BRUTE_FORCE["ip"]]
        failed = [r for r in mine if r["event_type"] == "login_failed"]
        self.assertGreaterEqual(len(failed), 8)
        self.assertEqual(mine[-1]["event_type"], "login_success")  # success comes after the failures
        # all failures within 2 minutes
        first, last = failed[0]["timestamp"], failed[-1]["timestamp"]
        self.assertLessEqual(_seconds(last) - _seconds(first), 120)

    def test_TC_I20_bad_line_count_gives_clear_error(self):
        for bad in ("0", "-5"):
            out = io.StringIO()
            with redirect_stdout(out):
                code = main([self.folder(), "--lines", bad])
            self.assertEqual(code, 1)
            self.assertIn("--lines must be a positive number", out.getvalue())
        self.assertFalse(os.path.exists(self.folder()))  # nothing written


def _seconds(ts):
    from datetime import datetime
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").timestamp()


if __name__ == "__main__":
    unittest.main()
