# Ingestion + Database

Takes in simulated security logs from 4 sources, checks each line, turns it
into a standard **LogEntry**, and saves it in the database. Also holds the
database schema for LogEntry, Alert and Incident.

**Owner:** Gauri Kaushik

## Files
| File | What it does |
|---|---|
| `schema.sql` | Tables: `log_entries`, `alerts`, `incidents` |
| `db.py` | Connect to the DB, save entries, query entries (other modules use this) |
| `parsers.py` | One parser per log source |
| `ingest.py` | Command line tool to load, show and export logs |
| `sample_logs/` | Simulated logs (includes a few bad lines on purpose) |
| `tests/` | 14 unit tests (TC-I01 to TC-I14) |

## Log sources
| Source | File | Format |
|---|---|---|
| auth | `auth*.txt` | syslog style (`sshd`, `sudo`) |
| network | `network*.csv` | firewall CSV |
| system | `system*.jsonl` | one JSON object per line |
| application | `app*.txt` | web access log |

Sample files use `.txt`/`.csv`/`.jsonl` because `.log` and `.db` files are
in `.gitignore`.

## How to run (from the repo root, Python 3.9+, no extra packages)
```
python -m ingestion.ingest ingestion/sample_logs          # load all sample logs
python -m ingestion.ingest --show --source auth           # see what was saved
python -m ingestion.ingest --show --since 2026-10-14T14:00:00Z
python -m ingestion.ingest --export log_entries.json      # JSON for other modules
python -m unittest discover -s ingestion/tests -t . -v    # run the tests
```
The database is `teamnova.db` in the folder you run from. Use `--db other.db`
or set `TEAMNOVA_DB` to change it. Running the same file twice does not add
duplicates.

## Using it from another module
```python
from ingestion.db import connect, get_log_entries

conn = connect()
entries = get_log_entries(conn, source="auth", since="2026-10-14T14:00:00Z")
```
Each entry is a dict in the shared format (see `shared/data_format.md`).

## What happens to bad lines
Bad lines are skipped and reported with the line number and reason (bad
timestamp, bad IP, wrong number of CSV columns, invalid JSON, unknown format).
The rest of the file still loads.
