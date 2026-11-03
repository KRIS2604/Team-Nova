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
| `generate_logs.py` | Makes a big simulated log set with planted attacks (Sprint 2) |
| `sample_logs/` | Simulated logs (includes a few bad lines on purpose) |
| `tests/` | 19 unit tests (TC-I01 to TC-I14, TC-I16 to TC-I20) |

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

## Bigger test data (Sprint 2)
```
python -m ingestion.generate_logs big_logs --lines 2000 --seed 42
python -m ingestion.ingest big_logs --db big.db
```
Writes `auth.txt`, `network.csv`, `system.jsonl` and `app_access.txt` into
`big_logs/` (about 2,000 normal lines over one day, 1 Nov 2026 UTC). The same
`--seed` always gives the same files. Three attacks are planted for testing
detection:

| Attack | Who | When (UTC) |
|---|---|---|
| Brute force: 10 failed logins, then success | `rpatel` from 198.51.100.23 | 06:15 to 06:16 |
| Port scan: 20 ports, mostly blocked | 203.0.113.77 -> 10.0.0.20 | 10:40 to 10:41 |
| Repeated access: 6 x 403 on `/admin` pages | `kwilson` from 10.0.0.66 | 15:05 to 15:07 |

`big_logs/` and `*.db` are in `.gitignore`, so don't commit them.
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
