"""Write the incident report.

If OPENAI_API_KEY is set, the agent asks an LLM to write the title, summary
and recommendations. If there is no key, or the LLM call fails, it uses
the built-in templates below, so the agent always produces a report.
"""

import json
import os
import urllib.request
from collections import Counter

OPENAI_URL = "https://api.openai.com/v1/chat/completions"


def _hhmm(ts):
    return ts[11:16]


def _facts(alerts, context):
    """Count the things we look for in the logs."""
    events = Counter(e["event_type"] for e in context)
    return {
        "users": sorted({a["user"] for a in alerts if a["user"]}),
        "ips": sorted({a["ip"] for a in alerts if a["ip"]}),
        "hosts": sorted({e["host"] for e in context if e.get("host")} | {a["host"] for a in alerts if a["host"]}),
        "failed": events["login_failed"],
        "success_after_fail": any(e["event_type"] == "login_success" for e in context) and events["login_failed"] > 0,
        "blocked": events["connection_blocked"],
        "allowed": events["connection_allowed"],
        "file_reads": events["file_read"],
        "forbidden": events["http_403"],
        "processes": events["process_start"],
        "start": _hhmm(min([e["timestamp"] for e in context] + [alerts[0]["timestamp"]])),
        "end": _hhmm(max([e["timestamp"] for e in context] + [alerts[-1]["timestamp"]])),
    }


def template_report(alerts, context):
    """Plain-English report from simple rules. Returns (title, summary, recommendations)."""
    f = _facts(alerts, context)
    who = f["users"][0] if f["users"] else (f["ips"][0] if f["ips"] else "unknown source")
    ip = f["ips"][0] if f["ips"] else "an unknown IP"

    if f["failed"] >= 3 and f["success_after_fail"]:
        return (
            "Possible brute-force login on %s" % who,
            "%d failed logins for %s from %s, followed by a successful login (%s to %s UTC). "
            "The password may have been guessed." % (f["failed"], who, ip, f["start"], f["end"]),
            "Reset %s's password, check what the account did after logging in, and block %s." % (who, ip),
        )
    if f["failed"] >= 1 and not f["success_after_fail"]:
        return (
            "Failed login attempts for %s" % who,
            "%d failed login(s) for %s from %s (%s to %s UTC). No successful login followed."
            % (f["failed"], who, ip, f["start"], f["end"]),
            "Check if %s is a real account. Block %s if the attempts continue." % (who, ip),
        )
    if f["blocked"] >= 5 and (f["allowed"] or f["file_reads"]):
        return (
            "Possible data theft from %s" % ip,
            "%s scanned %d ports (blocked), then read files and made a large outbound "
            "connection (%s to %s UTC). This looks like a scan followed by data being sent out."
            % (ip, f["blocked"], f["start"], f["end"]),
            "Isolate %s, check which files were read, and find out what data was sent out." % ip,
        )
    if f["blocked"] >= 5:
        return (
            "Port scan from %s" % ip,
            "%s tried %d ports and all were blocked (%s to %s UTC)." % (ip, f["blocked"], f["start"], f["end"]),
            "Watch %s for more activity and block it if the scan continues." % ip,
        )
    if f["forbidden"] >= 3:
        return (
            "Repeated access attempts on admin page by %s" % who,
            "%s got %d 'forbidden' responses on admin pages (%s to %s UTC)." % (who, f["forbidden"], f["start"], f["end"]),
            "Check if %s should have admin access. If not, remind them of the access rules." % who,
        )
    if f["processes"]:
        host = f["hosts"][0] if f["hosts"] else "the host"
        return (
            "Unusual process on %s" % host,
            "A process started on %s that is not normally seen (%s UTC)." % (host, f["start"]),
            "Check if the process is a known job (for example a backup). If not, stop it and investigate.",
        )
    return (
        "Suspicious activity involving %s" % who,
        "Alerts involving %s (%s to %s UTC): %s."
        % (who, f["start"], f["end"], "; ".join(a["reason"] for a in alerts)),
        "Review the related logs and confirm whether this activity is expected.",
    )


def _ask_llm(alerts, context, api_key, model):
    """Ask the LLM for the report. Returns (title, summary, recommendations)."""
    prompt = (
        "You are a security analyst. Write a short incident report in plain English "
        "for a new analyst. Reply with JSON only: "
        '{"title": "...", "summary": "2-3 sentences", "recommendations": "1-2 sentences"}.\n\n'
        "Alerts:\n" + json.dumps([{k: a[k] for k in ("timestamp", "severity", "reason", "user", "ip", "host")} for a in alerts], indent=1)
        + "\n\nRelated log lines:\n" + "\n".join(e["raw_data"] for e in context[:40])
    )
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_object"},
    }).encode("utf-8")
    req = urllib.request.Request(OPENAI_URL, data=body, headers={
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    out = json.loads(data["choices"][0]["message"]["content"])
    return out["title"], out["summary"], out["recommendations"]


def write_report(alerts, context, use_llm=True, llm=None):
    """Return a report dict plus where it came from ("llm" or "template")."""
    f = _facts(alerts, context)
    api_key = os.environ.get("OPENAI_API_KEY", "")
    have_key = api_key and api_key != "your-key-here"
    source = "template"
    title, summary, recs = template_report(alerts, context)

    if use_llm and (have_key or llm):
        try:
            ask = llm or (lambda a, c: _ask_llm(a, c, api_key, os.environ.get("OPENAI_MODEL", "gpt-4o-mini")))
            title, summary, recs = ask(alerts, context)
            source = "llm"
        except Exception as e:  # any LLM problem -> keep the template report
            print("  LLM failed (%s), using template report" % e.__class__.__name__)

    return {
        "title": title,
        "summary": summary,
        "affected_systems": f["hosts"],
        "recommendations": recs,
        "source": source,
    }
