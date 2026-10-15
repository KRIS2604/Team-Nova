"""Parsers that turn raw log lines into the shared LogEntry format.

Each source writes logs in a different format:
    auth        -> syslog-style text   (auth.txt)
    network     -> firewall CSV        (network.csv)
    system      -> JSON, one per line  (system.jsonl)
    application -> web access log      (app_access.txt)

Every parser returns either a LogEntry dict or raises ParseError with a
short reason. The ingest script counts the errors and keeps going, so one
bad line never stops the whole file.
"""

import csv
import ipaddress
import json
import re
from datetime import datetime, timezone

SOURCES = ("auth", "network", "system", "application")


class ParseError(Exception):
    pass


# ---------- shared checks ----------

def normalize_timestamp(value):
    """Return the time as UTC 'YYYY-MM-DDTHH:MM:SSZ' or raise ParseError."""
    if not value:
        raise ParseError("missing timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ParseError("bad timestamp '%s'" % value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # treat times with no zone as UTC
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_ip(value):
    """Return the IP if valid, None if empty, or raise ParseError."""
    if value is None or value.strip() in ("", "-"):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ParseError("bad IP address '%s'" % value)


def make_entry(source, timestamp, event_type, raw, user=None, ip=None, host=None):
    if source not in SOURCES:
        raise ParseError("unknown source '%s'" % source)
    if not event_type:
        raise ParseError("missing event type")
    return {
        "timestamp": normalize_timestamp(timestamp),
        "source": source,
        "event_type": event_type,
        "user": user or None,
        "ip": check_ip(ip),
        "host": host or None,
        "raw_data": raw,
    }


# ---------- auth (syslog-style) ----------
# 2026-10-14T14:03:12Z auth-server-01 sshd[1023]: Failed password for jsmith from 192.168.1.45 port 52211

AUTH_LINE = re.compile(r"^(\S+)\s+(\S+)\s+([\w-]+)(?:\[\d+\])?:\s+(.*)$")
AUTH_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
AUTH_OK = re.compile(r"Accepted password for (\S+) from (\S+)")
AUTH_SUDO = re.compile(r"^(\S+) : .*COMMAND=")
AUTH_LOGOUT = re.compile(r"session closed for user (\S+)")


def parse_auth(line):
    m = AUTH_LINE.match(line)
    if not m:
        raise ParseError("line does not match auth log format")
    timestamp, host, program, message = m.groups()
    user = ip = None
    if AUTH_FAILED.search(message):
        user, ip = AUTH_FAILED.search(message).groups()
        event = "login_failed"
    elif AUTH_OK.search(message):
        user, ip = AUTH_OK.search(message).groups()
        event = "login_success"
    elif program == "sudo" and AUTH_SUDO.search(message):
        user = AUTH_SUDO.search(message).group(1)
        event = "sudo_command"
    elif AUTH_LOGOUT.search(message):
        user = AUTH_LOGOUT.search(message).group(1)
        event = "logout"
    else:
        event = "auth_other"
    return make_entry("auth", timestamp, event, line, user=user, ip=ip, host=host)


# ---------- network (firewall CSV) ----------
# timestamp,host,src_ip,dst_ip,dst_port,protocol,action,bytes

NETWORK_COLUMNS = ["timestamp", "host", "src_ip", "dst_ip", "dst_port",
                   "protocol", "action", "bytes"]


def parse_network(line):
    values = next(csv.reader([line]))
    if len(values) != len(NETWORK_COLUMNS):
        raise ParseError("expected %d columns, got %d" % (len(NETWORK_COLUMNS), len(values)))
    row = dict(zip(NETWORK_COLUMNS, [v.strip() for v in values]))
    check_ip(row["dst_ip"])  # check both IPs, store the source IP
    action = row["action"].lower()
    if action not in ("allow", "block"):
        raise ParseError("unknown firewall action '%s'" % row["action"])
    event = "connection_allowed" if action == "allow" else "connection_blocked"
    return make_entry("network", row["timestamp"], event, line,
                      ip=row["src_ip"], host=row["host"])


# ---------- system (JSON lines) ----------
# {"timestamp": "...", "host": "web-server-02", "event": "process_start", "user": "root", ...}

def parse_system(line):
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        raise ParseError("not valid JSON")
    if not isinstance(data, dict):
        raise ParseError("JSON line is not an object")
    return make_entry("system", data.get("timestamp"), data.get("event"), line,
                      user=data.get("user"), ip=data.get("ip"), host=data.get("host"))


# ---------- application (web access log) ----------
# 10.0.0.33 - tnguyen [12/Oct/2026:09:14:10 +0000] "GET /admin HTTP/1.1" 403 512

ACCESS_LINE = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\S+)')


def parse_application(line, host="app-server-01"):
    m = ACCESS_LINE.match(line)
    if not m:
        raise ParseError("line does not match web access log format")
    ip, user, when, method, path, status, size = m.groups()
    try:
        dt = datetime.strptime(when, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        raise ParseError("bad timestamp '%s'" % when)
    event = "http_%s" % status
    return make_entry("application", dt.isoformat(), event, line,
                      user=None if user == "-" else user, ip=ip, host=host)


PARSERS = {
    "auth": parse_auth,
    "network": parse_network,
    "system": parse_system,
    "application": parse_application,
}
