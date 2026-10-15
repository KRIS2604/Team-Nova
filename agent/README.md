# Investigation Agent

Takes new alerts, groups the related ones into **incidents**, looks up the
surrounding logs for context, and writes a plain-English **incident report**
(title, summary, affected systems, recommendations). Saves incidents in the
shared format (see `shared/data_format.md`) so the dashboard can show them.

**Owner:** Kris Sathwara

## How it works
1. **Get new alerts.** Alerts with no incident yet. Until the Detection Engine
   is ready, `mock_alerts.json` gives 8 alerts that point at real log entries
   from `ingestion/sample_logs`.
2. **Group them.** Two alerts are the same incident if they share a user or an
   IP and are within 30 minutes of each other (chains count too).
3. **Gather context.** Pulls log entries with the same users/IPs from 15 minutes
   before to 15 minutes after the incident (uses Gauri's database).
4. **Write the report.** Uses an LLM if `OPENAI_API_KEY` is set. With no key, or
   if the LLM call fails, it uses built-in templates, so it always works.
5. **Save.** Adds the incident to the `incidents` table and links its alerts.

## Files
| File | What it does |
|---|---|
| `mock_alerts.json` | 8 mock alerts (until Detection is ready) |
| `alerts.py` | Load mock alerts, get alerts not yet in an incident |
| `correlate.py` | Group related alerts, gather log context |
| `report.py` | Write the report (LLM or template) |
| `investigate.py` | Command line tool that runs all the steps |
| `tests/` | 12 unit tests (TC-A01 to TC-A12) |

## How to run (from the repo root, Python 3.9+, no extra packages)
```
python -m ingestion.ingest ingestion/sample_logs      # 1. load the logs
python -m agent.investigate --mock                     # 2. add mock alerts + investigate
python -m agent.investigate --show                     # see all incidents
python -m agent.investigate --export incidents.json    # JSON for the dashboard
python -m unittest discover -s agent/tests -t . -v     # run the tests
```
Running `--mock` again does not add duplicates. Don't commit `incidents.json`.

## Using an LLM (optional)
Set `OPENAI_API_KEY` (and optionally `OPENAI_MODEL`, default `gpt-4o-mini`)
in your terminal, never in the code. Without it, template reports are used.

## Sample result (8 mock alerts -> 5 incidents)
| Incident | Severity | Alerts |
|---|---|---|
| Possible brute-force login on jsmith | critical | alert_001, alert_002 |
| Possible data theft from 10.0.0.87 | high | alert_003, alert_004, alert_005 |
| Repeated access attempts on admin page by tnguyen | medium | alert_007 |
| Unusual process on web-server-02 | low | alert_006 |
| Failed login attempts for admin | low | alert_008 |
