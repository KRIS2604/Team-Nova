"""Group related alerts into incidents and collect context for each one.

Two alerts belong to the same incident if they share a user or an IP and
happened within WINDOW_MINUTES of each other. Chains count too: if A links
to B and B links to C, all three are one incident.
"""

from datetime import datetime, timedelta

WINDOW_MINUTES = 30
CONTEXT_MINUTES = 15
SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def parse_time(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def fmt_time(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _linked(a, b, window_minutes):
    close = abs(parse_time(a["timestamp"]) - parse_time(b["timestamp"])) <= timedelta(minutes=window_minutes)
    same_user = a["user"] and a["user"] == b["user"]
    same_ip = a["ip"] and a["ip"] == b["ip"]
    return close and bool(same_user or same_ip)


def group_alerts(alerts, window_minutes=WINDOW_MINUTES):
    """Return a list of groups (each a list of alerts), oldest group first."""
    parent = list(range(len(alerts)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(alerts)):
        for j in range(i + 1, len(alerts)):
            if _linked(alerts[i], alerts[j], window_minutes):
                parent[find(j)] = find(i)

    groups = {}
    for i, a in enumerate(alerts):
        groups.setdefault(find(i), []).append(a)
    result = [sorted(g, key=lambda a: a["timestamp"]) for g in groups.values()]
    return sorted(result, key=lambda g: g[0]["timestamp"])


def highest_severity(alerts):
    return max((a["severity"] for a in alerts), key=SEVERITY_ORDER.index)


def gather_context(conn, alerts, minutes=CONTEXT_MINUTES):
    """Find log entries around the incident that involve the same users or IPs.

    This is the extra information an analyst would normally look up by hand.
    """
    users = sorted({a["user"] for a in alerts if a["user"]})
    ips = sorted({a["ip"] for a in alerts if a["ip"]})
    start = fmt_time(parse_time(alerts[0]["timestamp"]) - timedelta(minutes=minutes))
    end = fmt_time(parse_time(alerts[-1]["timestamp"]) + timedelta(minutes=minutes))

    conditions, params = [], [start, end]
    if users:
        conditions.append("username IN (%s)" % ",".join("?" * len(users)))
        params += users
    if ips:
        conditions.append("ip IN (%s)" % ",".join("?" * len(ips)))
        params += ips
    if not conditions:
        return []

    sql = ("SELECT * FROM log_entries WHERE timestamp >= ? AND timestamp <= ? AND (%s) "
           "ORDER BY timestamp, id" % " OR ".join(conditions))
    return [dict(r) for r in conn.execute(sql, params)]
