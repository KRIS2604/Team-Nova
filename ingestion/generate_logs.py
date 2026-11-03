"""Make a big set of simulated logs with planted attacks.

Writes 4 files in the same formats as ingestion/sample_logs, so ingest.py
can load them straight away:
    auth.txt  network.csv  system.jsonl  app_access.txt

Most lines are normal traffic. Three attacks are planted at known times so
the detection engine can be tested on bigger data:
    brute force     - 10 failed logins for one user from one IP in under
                      2 minutes, then a successful login
    port scan       - one IP hitting 20 different ports in about 1 minute,
                      mostly blocked
    repeated access - one user getting 6 x 403 on /admin pages in a few minutes

Examples (run from the repo root):
    python -m ingestion.generate_logs big_logs
    python -m ingestion.generate_logs big_logs --lines 5000 --seed 7

The same --seed always gives the same files, so tests are repeatable.
"""

import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone

START = datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
SPAN_SECONDS = 24 * 60 * 60  # one day of logs

# Share of normal lines that go to each file.
SHARES = {"auth": 0.30, "network": 0.35, "system": 0.15, "app": 0.20}

FILE_NAMES = {
    "auth": "auth.txt",
    "network": "network.csv",
    "system": "system.jsonl",
    "app": "app_access.txt",
}

NETWORK_HEADER = "timestamp,host,src_ip,dst_ip,dst_port,protocol,action,bytes"
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# Normal users and their usual machines.
USERS = {
    "asmith": "10.0.0.12",
    "mlee": "10.0.0.14",
    "tnguyen": "10.0.0.33",
    "jgarcia": "10.0.0.41",
    "pwhite": "10.0.0.52",
    "dkumar": "10.0.0.58",
}
SERVERS = ["10.0.0.20", "10.0.0.21", "10.0.0.30"]
NORMAL_PORTS = [22, 80, 443, 445, 3306, 8080]
SYSTEM_HOSTS = ["web-server-02", "file-server-01", "db-server-01"]
SYSTEM_EVENTS = ["process_start", "service_restart", "disk_warning",
                 "file_read", "config_change"]
APP_PAGES = ["/", "/dashboard", "/reports", "/profile", "/search", "/help"]

# Planted attacks (fixed so tests and Brandon know what to look for).
BRUTE_FORCE = {"user": "rpatel", "ip": "198.51.100.23", "failed": 10,
               "start": START + timedelta(hours=6, minutes=15)}
PORT_SCAN = {"ip": "203.0.113.77", "target": "10.0.0.20",
             "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                       443, 445, 993, 1433, 3306, 3389, 5432, 5900, 8080, 8443],
             "start": START + timedelta(hours=10, minutes=40)}
ADMIN_ACCESS = {"user": "kwilson", "ip": "10.0.0.66", "count": 6,
                "paths": ["/admin", "/admin/users", "/admin/settings",
                          "/admin/logs", "/admin/login", "/admin"],
                "start": START + timedelta(hours=15, minutes=5)}


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def web_time(dt):
    return "%02d/%s/%04d:%02d:%02d:%02d +0000" % (
        dt.day, MONTHS[dt.month - 1], dt.year, dt.hour, dt.minute, dt.second)


def random_time(rng):
    return START + timedelta(seconds=rng.randrange(SPAN_SECONDS))


# ---------- one line of each format ----------

def auth_line(dt, pid, message):
    return "%s auth-server-01 %s: %s" % (iso(dt), pid, message)


def network_line(dt, src, dst, port, action, size):
    return "%s,fw-01,%s,%s,%d,tcp,%s,%d" % (iso(dt), src, dst, port, action, size)


def system_line(dt, host, event, user, **extra):
    data = {"timestamp": iso(dt), "host": host, "event": event, "user": user}
    data.update(extra)
    return json.dumps(data)


def app_line(dt, ip, user, method, path, status, size):
    return '%s - %s [%s] "%s %s HTTP/1.1" %d %d' % (
        ip, user, web_time(dt), method, path, status, size)


# ---------- normal traffic ----------

def normal_auth(rng, dt):
    user = rng.choice(list(USERS))
    ip = USERS[user]
    pid = "sshd[%d]" % rng.randint(1000, 9999)
    port = rng.randint(40000, 65000)
    roll = rng.random()
    if roll < 0.60:
        return auth_line(dt, pid, "Accepted password for %s from %s port %d ssh2" % (user, ip, port))
    if roll < 0.75:
        # a single typo, not an attack
        return auth_line(dt, pid, "Failed password for %s from %s port %d ssh2" % (user, ip, port))
    if roll < 0.88:
        return auth_line(dt, "sudo", "%s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=/usr/bin/apt update"
                         % (user, user))
    return auth_line(dt, pid, "pam_unix(sshd:session): session closed for user %s" % user)


def normal_network(rng, dt):
    user = rng.choice(list(USERS))
    port = rng.choice(NORMAL_PORTS)
    if rng.random() < 0.95:
        return network_line(dt, USERS[user], rng.choice(SERVERS), port, "allow", rng.randint(200, 90000))
    return network_line(dt, USERS[user], rng.choice(SERVERS), port, "block", 0)


def normal_system(rng, dt):
    host = rng.choice(SYSTEM_HOSTS)
    event = rng.choice(SYSTEM_EVENTS)
    if event == "process_start":
        return system_line(dt, host, event, "root", process="/opt/scripts/job_%d.sh" % rng.randint(1, 20))
    if event == "service_restart":
        return system_line(dt, host, event, "root", service=rng.choice(["nginx", "postgres", "cron"]))
    if event == "disk_warning":
        return system_line(dt, host, event, None, detail="disk /data %d%% full" % rng.randint(80, 95))
    if event == "file_read":
        user = rng.choice(list(USERS))
        return system_line(dt, host, event, user, ip=USERS[user],
                           path="/data/shared/file_%d.txt" % rng.randint(1, 500))
    return system_line(dt, host, event, "root", detail="updated /etc/app/config_%d.yml" % rng.randint(1, 10))


def normal_app(rng, dt):
    user = rng.choice(list(USERS))
    roll = rng.random()
    if roll < 0.90:
        return app_line(dt, USERS[user], user, "GET", rng.choice(APP_PAGES), 200, rng.randint(500, 9000))
    if roll < 0.97:
        return app_line(dt, USERS[user], user, "GET", "/page-%d" % rng.randint(1, 300), 404, 128)
    # one-off 403, not an attack
    return app_line(dt, USERS[user], user, "GET", "/admin", 403, 512)


NORMAL = {"auth": normal_auth, "network": normal_network,
          "system": normal_system, "app": normal_app}


# ---------- planted attacks ----------

def planted_brute_force(rng):
    a = BRUTE_FORCE
    lines = []
    t = a["start"]
    for i in range(a["failed"]):
        lines.append((t, auth_line(t, "sshd[%d]" % (7000 + i), "Failed password for %s from %s port %d ssh2"
                                   % (a["user"], a["ip"], 51000 + i))))
        t += timedelta(seconds=rng.randint(5, 10))  # 10 tries in under 2 minutes
    lines.append((t, auth_line(t, "sshd[%d]" % 7100, "Accepted password for %s from %s port %d ssh2"
                               % (a["user"], a["ip"], 51100))))
    return lines


def planted_port_scan(rng):
    a = PORT_SCAN
    lines = []
    t = a["start"]
    for port in a["ports"]:
        action = "allow" if port in (80, 443) else "block"
        size = rng.randint(60, 400) if action == "allow" else 0
        lines.append((t, network_line(t, a["ip"], a["target"], port, action, size)))
        t += timedelta(seconds=rng.randint(1, 4))
    return lines


def planted_admin_access(rng):
    a = ADMIN_ACCESS
    lines = []
    t = a["start"]
    for i in range(a["count"]):
        method = "POST" if a["paths"][i] == "/admin/login" else "GET"
        lines.append((t, app_line(t, a["ip"], a["user"], method, a["paths"][i], 403, 512)))
        t += timedelta(seconds=rng.randint(15, 40))
    return lines


# ---------- main ----------

def generate(out_folder, lines=2000, seed=42):
    """Write the 4 log files. Returns a summary dict.

    Raises ValueError if lines is not a positive number.
    """
    if not isinstance(lines, int) or lines <= 0:
        raise ValueError("--lines must be a positive number (got %s)" % lines)

    rng = random.Random(seed)
    files = {name: [] for name in FILE_NAMES}  # name -> list of (time, line)

    # Split the normal lines between the files.
    counts = {name: int(lines * share) for name, share in SHARES.items()}
    counts["auth"] += lines - sum(counts.values())  # leftover goes to auth

    for name, n in counts.items():
        seen = set()
        while len(files[name]) < n:
            dt = random_time(rng)
            line = NORMAL[name](rng, dt)
            if line in seen:  # ingest.py would count an exact repeat as a duplicate
                continue
            seen.add(line)
            files[name].append((dt, line))

    attacks = {
        "brute_force": planted_brute_force(rng),
        "port_scan": planted_port_scan(rng),
        "admin_access": planted_admin_access(rng),
    }
    files["auth"] += attacks["brute_force"]
    files["network"] += attacks["port_scan"]
    files["app"] += attacks["admin_access"]

    os.makedirs(out_folder, exist_ok=True)
    written = {}
    for name, rows in files.items():
        rows.sort(key=lambda r: (r[0], r[1]))
        path = os.path.join(out_folder, FILE_NAMES[name])
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            if name == "network":
                f.write(NETWORK_HEADER + "\n")
            for _, line in rows:
                f.write(line + "\n")
        written[FILE_NAMES[name]] = len(rows)

    return {
        "folder": out_folder,
        "seed": seed,
        "files": written,
        "attacks": {
            "brute_force": "%s from %s, %d failed logins then success, %s to %s" % (
                BRUTE_FORCE["user"], BRUTE_FORCE["ip"], BRUTE_FORCE["failed"],
                iso(attacks["brute_force"][0][0]), iso(attacks["brute_force"][-1][0])),
            "port_scan": "%s -> %s, %d ports, %s to %s" % (
                PORT_SCAN["ip"], PORT_SCAN["target"], len(PORT_SCAN["ports"]),
                iso(attacks["port_scan"][0][0]), iso(attacks["port_scan"][-1][0])),
            "admin_access": "%s from %s, %d x 403 on /admin pages, %s to %s" % (
                ADMIN_ACCESS["user"], ADMIN_ACCESS["ip"], ADMIN_ACCESS["count"],
                iso(attacks["admin_access"][0][0]), iso(attacks["admin_access"][-1][0])),
        },
    }


def print_summary(summary):
    print("Wrote logs to %s (seed %s)" % (summary["folder"], summary["seed"]))
    for name, n in summary["files"].items():
        print("  %-16s %5d lines" % (name, n))
    print("  TOTAL            %5d lines" % sum(summary["files"].values()))
    print("Planted attacks:")
    for name, text in summary["attacks"].items():
        print("  %-13s %s" % (name, text))


def main(argv=None):
    p = argparse.ArgumentParser(description="Make simulated Team Nova logs with planted attacks")
    p.add_argument("out_folder", help="folder to write the 4 log files into")
    p.add_argument("--lines", type=int, default=2000, help="normal lines in total (default 2000)")
    p.add_argument("--seed", type=int, default=42, help="random seed (default 42)")
    args = p.parse_args(argv)

    try:
        summary = generate(args.out_folder, args.lines, args.seed)
    except ValueError as e:
        print("Error: %s" % e)
        return 1
    print_summary(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
