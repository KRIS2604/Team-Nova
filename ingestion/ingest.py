"""Load log files into the Team Nova database.

Examples (run from the repo root):
    python -m ingestion.ingest ingestion/sample_logs
    python -m ingestion.ingest ingestion/sample_logs/auth.txt --db test.db
    python -m ingestion.ingest --show --source auth
    python -m ingestion.ingest --export log_entries.json
"""

import argparse
import json
import os
import sys

from ingestion import db
from ingestion.parsers import PARSERS, ParseError

# Which parser to use, based on the file name.
FILE_TYPES = [
    ("auth", ".txt", "auth"),
    ("network", ".csv", "network"),
    ("system", ".jsonl", "system"),
    ("app", ".txt", "application"),
]


def detect_source(path):
    name = os.path.basename(path).lower()
    for prefix, ext, source in FILE_TYPES:
        if name.startswith(prefix) and name.endswith(ext):
            return source
    return None


def ingest_file(conn, path, source=None):
    """Read one file and save every valid line.

    Returns a summary dict: read, loaded, duplicates, rejected, errors.
    """
    source = source or detect_source(path)
    if source not in PARSERS:
        raise ValueError(
            "Can't tell what kind of log '%s' is. Name it auth*.txt, network*.csv, "
            "system*.jsonl or app*.txt, or pass --source." % os.path.basename(path))
    parse = PARSERS[source]
    summary = {"file": os.path.basename(path), "source": source,
               "read": 0, "loaded": 0, "duplicates": 0, "rejected": 0, "errors": []}

    with open(path, encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip() or line.startswith("#"):
                continue
            if source == "network" and line.lower().startswith("timestamp,"):
                continue  # CSV header
            summary["read"] += 1
            try:
                entry = parse(line)
            except ParseError as e:
                summary["rejected"] += 1
                summary["errors"].append("line %d: %s" % (line_no, e))
                continue
            if db.insert_log_entry(conn, entry) == "inserted":
                summary["loaded"] += 1
            else:
                summary["duplicates"] += 1
    conn.commit()
    return summary


def ingest_path(conn, path, source=None):
    """Ingest a single file or every log file in a folder."""
    if os.path.isdir(path):
        files = sorted(os.path.join(path, n) for n in os.listdir(path)
                       if detect_source(n))
        return [ingest_file(conn, f) for f in files]
    return [ingest_file(conn, path, source)]


def print_summary(results):
    totals = {"read": 0, "loaded": 0, "duplicates": 0, "rejected": 0}
    for r in results:
        print("%-16s %-12s read %3d | loaded %3d | duplicates %3d | rejected %3d"
              % (r["file"], r["source"], r["read"], r["loaded"],
                 r["duplicates"], r["rejected"]))
        for err in r["errors"]:
            print("    rejected %s" % err)
        for k in totals:
            totals[k] += r[k]
    print("TOTAL: read %(read)d, loaded %(loaded)d, duplicates %(duplicates)d, "
          "rejected %(rejected)d" % totals)


def main(argv=None):
    p = argparse.ArgumentParser(description="Team Nova log ingestion")
    p.add_argument("path", nargs="?", help="log file or folder to load")
    p.add_argument("--db", default=db.DEFAULT_DB, help="database file (default teamnova.db)")
    p.add_argument("--source", choices=list(PARSERS), help="force the log type")
    p.add_argument("--show", action="store_true", help="print stored log entries")
    p.add_argument("--since", help="with --show/--export: only entries at or after this time")
    p.add_argument("--limit", type=int, help="with --show: max rows")
    p.add_argument("--export", metavar="FILE", help="write stored entries to a JSON file")
    args = p.parse_args(argv)

    if not (args.path or args.show or args.export):
        p.print_help()
        return 1

    conn = db.connect(args.db)

    if args.path:
        if not os.path.exists(args.path):
            print("Error: '%s' not found" % args.path)
            return 1
        try:
            print_summary(ingest_path(conn, args.path, args.source))
        except ValueError as e:
            print("Error: %s" % e)
            return 1

    if args.show:
        rows = db.get_log_entries(conn, source=args.source, since=args.since, limit=args.limit)
        for r in rows:
            print("%s  %-11s %-20s user=%-8s ip=%-15s host=%s" % (
                r["timestamp"], r["source"], r["event_type"], r["user"] or "-",
                r["ip"] or "-", r["host"] or "-"))
        print("(%d entries)" % len(rows))

    if args.export:
        rows = db.get_log_entries(conn, source=args.source, since=args.since)
        with open(args.export, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        print("Wrote %d entries to %s" % (len(rows), args.export))

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
