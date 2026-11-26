"""Team Nova web app: serves the dashboard and the backend API (R7, R8).

One command runs the whole pipeline and opens it in the browser:
    python -m dashboard.server             # then open http://localhost:8000

On start it makes sure the database has data:
    1. Ingestion loads the log files (Gauri)          -> log_entries
    2. Alerts are loaded (mock until Detection is in)  -> alerts
    3. The Investigation Agent groups them (Kris)      -> incidents
Then it serves the dashboard and these endpoints:
    GET  /api/health                      status + row counts
    GET  /api/alerts                      all alerts, newest first
    GET  /api/incidents                   all incidents with report + timeline
    GET  /api/incidents/<id>              one incident
    POST /api/alerts/<id>/feedback        {"is_false_positive": true | false | null}

Options:
    --port 8000       (or the PORT environment variable, used by hosting sites)
    --host 127.0.0.1  (use 0.0.0.0 when deployed)
    --db teamnova.db
    --logs ingestion/sample_logs
    --fresh           delete the database and rebuild it from the logs
Standard Python only, no installs.
"""

import argparse
import json
import mimetypes
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ingestion import db
from ingestion.ingest import ingest_path
from agent.alerts import load_mock_alerts
from agent.investigate import investigate, get_incidents

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(DASHBOARD_DIR)
DEFAULT_LOGS = os.path.join(REPO_DIR, "ingestion", "sample_logs")
STATIC_FILES = {"/": "index.html", "/index.html": "index.html",
                "/app.js": "app.js", "/style.css": "style.css"}


# ---------- pipeline ----------

def setup_data(db_path, logs=DEFAULT_LOGS, fresh=False, use_llm=None):
    """Run ingestion -> alerts -> agent so the dashboard has real data.

    Safe to run again: duplicate log lines and alerts are skipped, and only
    new alerts become incidents. Returns a short summary dict.
    """
    if fresh and os.path.exists(db_path):
        os.remove(db_path)
    if use_llm is None:
        key = os.environ.get("OPENAI_API_KEY", "")
        use_llm = bool(key) and key != "your-key-here"
    conn = db.connect(db_path)
    try:
        results = ingest_path(conn, logs)
        loaded = sum(r["loaded"] for r in results)
        alerts_added, _ = load_mock_alerts(conn)
        created = investigate(conn, use_llm=use_llm)
        return {"logs_loaded": loaded, "alerts_added": alerts_added,
                "incidents_created": len(created)}
    finally:
        conn.close()


# ---------- data for the API ----------

def _alert_dict(row):
    fp = row["is_false_positive"]
    return {
        "id": row["id"],
        "incident_id": row["incident_id"],
        "log_entry_id": row["log_entry_id"],
        "timestamp": row["timestamp"],
        "source": row["source"],
        "severity": row["severity"],
        "reason": row["reason"],
        "is_false_positive": None if fp is None else bool(fp),
    }


ALERT_SQL = """SELECT a.*, l.source FROM alerts a
               JOIN log_entries l ON l.id = a.log_entry_id"""


def list_alerts(conn):
    rows = conn.execute(ALERT_SQL + " ORDER BY a.timestamp DESC, a.id").fetchall()
    return [_alert_dict(r) for r in rows]


def get_alert(conn, alert_id):
    row = conn.execute(ALERT_SQL + " WHERE a.id = ?", (alert_id,)).fetchone()
    return _alert_dict(row) if row else None


def set_feedback(conn, alert_id, is_false_positive):
    """Save analyst feedback (R8). Returns the updated alert or None if not found."""
    value = None if is_false_positive is None else int(is_false_positive)
    cur = conn.execute("UPDATE alerts SET is_false_positive = ? WHERE id = ?", (value, alert_id))
    conn.commit()
    return get_alert(conn, alert_id) if cur.rowcount else None


def health(conn):
    count = lambda t: conn.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0]
    return {"status": "ok", "log_entries": count("log_entries"),
            "alerts": count("alerts"), "incidents": count("incidents")}


# ---------- web server ----------

class Handler(BaseHTTPRequestHandler):
    db_path = db.DEFAULT_DB
    quiet = False

    def log_message(self, fmt, *args):
        if not self.quiet:
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _send(self, status, body, ctype="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, message):
        self._send(status, {"error": message})

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in STATIC_FILES:
            name = STATIC_FILES[path]
            with open(os.path.join(DASHBOARD_DIR, name), "rb") as f:
                ctype = mimetypes.guess_type(name)[0] or "text/plain"
                return self._send(200, f.read(), ctype + "; charset=utf-8")
        if not path.startswith("/api/"):
            return self._error(404, "Page not found")

        conn = db.connect(self.db_path)
        try:
            if path == "/api/health":
                return self._send(200, health(conn))
            if path == "/api/alerts":
                return self._send(200, list_alerts(conn))
            if path == "/api/incidents":
                return self._send(200, get_incidents(conn, with_timeline=True))
            m = re.fullmatch(r"/api/incidents/([\w-]+)", path)
            if m:
                inc = [i for i in get_incidents(conn, with_timeline=True) if i["id"] == m.group(1)]
                if not inc:
                    return self._error(404, "No incident called %s" % m.group(1))
                return self._send(200, inc[0])
            return self._error(404, "Unknown API endpoint")
        finally:
            conn.close()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        m = re.fullmatch(r"/api/alerts/([\w-]+)/feedback", path)
        if not m:
            return self._error(404, "Unknown API endpoint")
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._error(400, "Body must be JSON")
        if not isinstance(body, dict) or "is_false_positive" not in body \
                or body["is_false_positive"] not in (True, False, None):
            return self._error(400, 'Send {"is_false_positive": true, false or null}')

        conn = db.connect(self.db_path)
        try:
            alert = set_feedback(conn, m.group(1), body["is_false_positive"])
        finally:
            conn.close()
        if alert is None:
            return self._error(404, "No alert called %s" % m.group(1))
        return self._send(200, alert)


def make_server(db_path, host="127.0.0.1", port=8000, quiet=False):
    handler = type("TeamNovaHandler", (Handler,), {"db_path": db_path, "quiet": quiet})
    return ThreadingHTTPServer((host, port), handler)


def main(argv=None):
    p = argparse.ArgumentParser(description="Team Nova web app (dashboard + API)")
    p.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)))
    p.add_argument("--db", default=db.DEFAULT_DB, help="database file (default teamnova.db)")
    p.add_argument("--logs", default=DEFAULT_LOGS, help="log file or folder to load on start")
    p.add_argument("--fresh", action="store_true", help="delete the database and rebuild it")
    args = p.parse_args(argv)

    if not os.path.exists(args.logs):
        print("Error: '%s' not found" % args.logs)
        return 1
    s = setup_data(args.db, args.logs, fresh=args.fresh)
    print("Data ready: %(logs_loaded)d new log lines, %(alerts_added)d new alerts, "
          "%(incidents_created)d new incidents" % s)

    server = make_server(args.db, args.host, args.port)
    shown = "localhost" if args.host in ("127.0.0.1", "0.0.0.0") else args.host
    print("Dashboard running at http://%s:%d  (Ctrl+C to stop)" % (shown, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
