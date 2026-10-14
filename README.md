# Team Nova — AI-Driven Security Log Monitoring and Incident Response System

CSCE 4901/4902 Capstone, University of North Texas — Fall 2026

## About
Security teams deal with huge amounts of logs and alerts, and most alerts come
with no context. Our system takes in simulated security logs, detects unusual
activity, groups related alerts into incidents, and uses an AI agent to write a
plain-English incident report. Analysts review reports on a dashboard and mark
alerts as false positive or real, which helps improve detection over time.

## Team
| Member | Sprint 1 Area |
|---|---|
| Gauri Kaushik | Ingestion + Database |
| Brandon Vojtkofsky | Detection Engine |
| Kris Sathwara | Investigation Agent |
| Sahil Chaudhari | Dashboard (frontend + API) |

## Planned Tech Stack
- Backend: Python 3
- Database: PostgreSQL
- AI: LLM API (OpenAI or similar)
- Data: simulated/synthetic security logs

## Repo Structure
- `ingestion/` – log ingestion and DB schema
- `detection/` – rule-based + ML anomaly detection
- `agent/` – LLM incident investigation and reports
- `dashboard/` – analyst dashboard (frontend + backend API)
- `shared/` – common data format and mock data
- `docs/` – requirements, design, and sprint documents

## Status
Sprint 1 — building each module in parallel on mock data, integrating at the end of the sprint.

See CONTRIBUTING.md for branch and commit rules.
