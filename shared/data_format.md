# Shared Data Format (proposed by Gauri, Sprint 1)

Every module uses these three objects. The fields come from our ER diagram
and match the dashboard's mock data. **Please check and comment on the PR
before we lock this in.** If you need a change later, post on Discord first.

All times are UTC in ISO 8601 with a `Z`: `2026-10-14T14:05:40Z`.
IDs are strings with a prefix: `log_0001`, `alert_001`, `inc_001`.

## LogEntry (made by Ingestion)
| Field | Type | Example | Notes |
|---|---|---|---|
| id | string | `log_0007` | |
| timestamp | string | `2026-10-14T14:03:12Z` | UTC |
| source | string | `auth` | `auth`, `network`, `system`, `application` |
| event_type | string | `login_failed` | see list below |
| user | string or null | `jsmith` | stored as `username` in the DB |
| ip | string or null | `192.168.1.45` | source IP |
| host | string or null | `auth-server-01` | **new**: machine that wrote the log |
| raw_data | string | original line | never changed |

Event types in Sprint 1:
- auth: `login_failed`, `login_success`, `sudo_command`, `logout`, `auth_other`
- network: `connection_allowed`, `connection_blocked`
- system: whatever the log's `event` field says (`process_start`, `service_restart`, `disk_warning`, `file_read`, `config_change`)
- application: `http_<status>` (`http_200`, `http_403`, `http_404`)

## Alert (made by Detection)
| Field | Type | Notes |
|---|---|---|
| id | string | `alert_001` |
| log_entry_id | string | must be a real LogEntry id |
| incident_id | string or null | null until grouped |
| timestamp | string | UTC |
| severity | string | `low`, `medium`, `high`, `critical` |
| reason | string | plain English, e.g. "5 failed logins in 2 minutes for user jsmith" |
| is_false_positive | null / true / false | null = not reviewed yet (analyst feedback, R6) |

## Incident (made by Investigation Agent)
| Field | Type | Notes |
|---|---|---|
| id | string | `inc_001` |
| title | string | |
| status | string | `open`, `investigating`, `resolved` |
| severity | string | `low`, `medium`, `high`, `critical` |
| created_at | string | UTC |
| alert_ids | list of strings | worked out from `alerts.incident_id` |
| report | object | `{summary, affected_systems: [..], recommendations}` |

## Changes from the ER diagram
- Added `host` to LogEntry, so the agent can fill in `affected_systems`.
- DB column is `username` instead of `user` (`user` is a reserved word in PostgreSQL). The JSON field is still `user`.
- `alert_ids` is not stored on Incident. It comes from the alerts table, so it can't get out of sync.
