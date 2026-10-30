"""Investigation Agent: turn new alerts into incidents with a written report.

How to run (from the repo root):
    python -m ingestion.ingest ingestion/sample_logs     # 1. load logs (Gauri)
    python -m agent.investigate --mock                    # 2. add mock alerts + investigate
    python -m agent.investigate --show                    # see the incidents
    python -m agent.investigate --export incidents.json   # JSON for the dashboard
    python -m agent.investigate --timeline inc_004        # timeline for one incident (R6)
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from ingestion.db import connect, DEFAULT_DB
from agent.alerts import load_mock_alerts, get_new_alerts
from agent.correlate import group_alerts, gather_context, highest_severity
from agent.report import write_report
from agent.timeline import get_timeline, format_timeline


def _next_incident_id(conn):
    n = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    return "inc_%03d" % (n + 1)


def investigate(conn, use_llm=True, llm=None):
    """Group all new alerts into incidents, write reports, save them.

    Returns the list of incidents created (shared Incident format).
    """
    alerts = get_new_alerts(conn)
    created = []
    for group in group_alerts(alerts):
        context = gather_context(conn, group)
        report = write_report(group, context, use_llm=use_llm, llm=llm)
        inc_id = _next_incident_id(conn)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        severity = highest_severity(group)
        conn.execute(
            """INSERT INTO incidents (id, title, status, severity, created_at,
                   report_summary, report_affected_systems, report_recommendations)
               VALUES (?, ?, 'open', ?, ?, ?, ?, ?)""",
            (inc_id, report["title"], severity, now, report["summary"],
             json.dumps(report["affected_systems"]), report["recommendations"]),
        )
        conn.executemany("UPDATE alerts SET incident_id = ? WHERE id = ?", [(inc_id, a["id"]) for a in group])
        conn.commit()
        created.append({
            "id": inc_id,
            "title": report["title"],
            "status": "open",
            "severity": severity,
            "created_at": now,
            "alert_ids": [a["id"] for a in group],
            "report": {k: report[k] for k in ("summary", "affected_systems", "recommendations")},
            "report_source": report["source"],
            "evidence_logs": len(context),
        })
    return created


def get_incidents(conn, with_timeline=False):
    """All incidents in the shared Incident format (optionally with their timeline)."""
    out = []
    for r in conn.execute("SELECT * FROM incidents ORDER BY id"):
        alert_ids = [a[0] for a in conn.execute("SELECT id FROM alerts WHERE incident_id = ? ORDER BY id", (r["id"],))]
        out.append({
            "id": r["id"],
            "title": r["title"],
            "status": r["status"],
            "severity": r["severity"],
            "created_at": r["created_at"],
            "alert_ids": alert_ids,
            "report": {
                "summary": r["report_summary"],
                "affected_systems": json.loads(r["report_affected_systems"] or "[]"),
                "recommendations": r["report_recommendations"],
            },
        })
        if with_timeline:
            out[-1]["timeline"] = get_timeline(conn, r["id"])
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description="Team Nova Investigation Agent")
    p.add_argument("--db", default=DEFAULT_DB, help="database file (default teamnova.db)")
    p.add_argument("--mock", action="store_true", help="load mock alerts before investigating")
    p.add_argument("--no-llm", action="store_true", help="always use the template report")
    p.add_argument("--show", action="store_true", help="print all incidents")
    p.add_argument("--export", metavar="FILE", help="save all incidents (with timelines) as JSON")
    p.add_argument("--timeline", metavar="INCIDENT_ID", help="show the timeline for one incident, e.g. inc_004")
    args = p.parse_args(argv)

    conn = connect(args.db)
    if conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0] == 0:
        print("No log entries found. Run ingestion first:")
        print("  python -m ingestion.ingest ingestion/sample_logs")
        return 1

    if args.mock:
        added, skipped = load_mock_alerts(conn)
        print("Mock alerts: %d added%s" % (added, (", skipped (log not found): " + ", ".join(skipped)) if skipped else ""))

    if not (args.show or args.export or args.timeline) or args.mock:
        created = investigate(conn, use_llm=not args.no_llm)
        if not created:
            print("No new alerts to investigate.")
        for inc in created:
            print("%s [%s] %s  <- %s  (%s report, %d related logs)" % (
                inc["id"], inc["severity"], inc["title"], ", ".join(inc["alert_ids"]),
                inc["report_source"], inc["evidence_logs"]))

    if args.show:
        for inc in get_incidents(conn):
            print("\n%s [%s] %s (%s)" % (inc["id"], inc["severity"], inc["title"], inc["status"]))
            print("  Alerts: " + ", ".join(inc["alert_ids"]))
            print("  Summary: " + inc["report"]["summary"])
            print("  Affected: " + ", ".join(inc["report"]["affected_systems"]))
            print("  Recommendation: " + inc["report"]["recommendations"])

    if args.timeline:
        inc = [i for i in get_incidents(conn) if i["id"] == args.timeline]
        if not inc:
            print("No incident called %s. Run --show to see the incident IDs." % args.timeline)
            return 1
        print("\n%s [%s] %s" % (inc[0]["id"], inc[0]["severity"], inc[0]["title"]))
        print(format_timeline(get_timeline(conn, args.timeline)))

    if args.export:
        with open(args.export, "w", encoding="utf-8") as f:
            json.dump(get_incidents(conn, with_timeline=True), f, indent=2)
        print("Saved incidents to " + args.export)
    return 0


if __name__ == "__main__":
    sys.exit(main())
