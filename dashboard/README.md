# Dashboard

Analyst dashboard (frontend + backend API). Shows alerts and incidents with their reports and timelines, and lets analysts mark alerts as false positive or real (saved in the database).

**Owner:** Sahil Chaudhari

## Run it (from the repo root, Python 3.9+, no installs)

```
python -m dashboard.server
```

Then open http://localhost:8000 in your browser. Press Ctrl+C in the terminal to stop it.

On start the server runs the whole pipeline so the page has real data:
1. Ingestion loads `ingestion/sample_logs` into `teamnova.db`
2. Alerts are loaded (mock alerts from `agent/mock_alerts.json` until the Detection Engine is merged)
3. The Investigation Agent groups the alerts into incidents and writes the reports

Running it again is safe: nothing is loaded twice. Options:

| Option | What it does |
|---|---|
| `--fresh` | delete `teamnova.db` and rebuild it from the logs |
| `--port 8080` | use another port (default 8000, or the `PORT` env variable) |
| `--host 0.0.0.0` | listen on all addresses (needed when deployed) |
| `--logs <folder>` | load a different log folder |
| `--db <file>` | use a different database file |

If `OPENAI_API_KEY` is set (see `.env.example`), the agent writes the reports with the LLM. If not, it uses the template reports.

## API

| Method | Path | Returns |
|---|---|---|
| GET | `/api/health` | `{"status": "ok", "log_entries": 34, "alerts": 8, "incidents": 5}` |
| GET | `/api/alerts` | all alerts (shared Alert format), newest first |
| GET | `/api/incidents` | all incidents with `report`, `alert_ids` and `timeline` |
| GET | `/api/incidents/<id>` | one incident, 404 if not found |
| POST | `/api/alerts/<id>/feedback` | body `{"is_false_positive": true}` (or `false`, or `null` to undo); returns the updated alert, 400 for a bad body, 404 for an unknown alert |

## Tests

```
python -m unittest discover -s dashboard/tests -t . -v
```

7 tests (TC-D11 to TC-D17): incidents API, alerts API, feedback saved, error cases, single incident timeline, static files, no duplicates on restart.

## Files
- `server.py` – web server + API (standard library only)
- `index.html`, `app.js`, `style.css` – the dashboard page (gets data from the API)
- `tests/test_server.py` – API tests
