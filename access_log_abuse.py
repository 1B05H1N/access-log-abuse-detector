#!/usr/bin/env python3
"""Detect web abuse patterns in access logs.

Parses Common/Combined Log Format and flags likely credential stuffing,
endpoint enumeration (excessive 404s), automated scanners, and high error
rates per source IP, then emits indicators and a suggested blocklist.
Standard library only.
"""
import argparse
import json
import re
import sys
from collections import defaultdict

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)

DEFAULT_AUTH_RE = re.compile(r"(login|signin|sign-in|auth|token|session|oauth)", re.I)

SCANNER_UA_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nessus|"
    r"nuclei|zgrab|zmap|hydra|feroxbuster|python-requests|go-http-client)", re.I)

DEFAULTS = {
    "auth_fail_threshold": 10,
    "notfound_threshold": 20,
    "min_requests_for_rate": 20,
    "error_rate_threshold": 0.5,
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def parse_line(line):
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    return {
        "ip": d["ip"],
        "method": d["method"],
        "path": d["path"],
        "status": int(d["status"]),
        "ua": d.get("ua") or "",
    }


def aggregate(entries, auth_re=DEFAULT_AUTH_RE):
    stats = defaultdict(lambda: {
        "requests": 0, "auth_fail": 0, "not_found": 0, "errors": 0,
        "paths": set(), "uas": set(),
    })
    for e in entries:
        s = stats[e["ip"]]
        s["requests"] += 1
        s["paths"].add(e["path"])
        if e["ua"]:
            s["uas"].add(e["ua"])
        if e["status"] >= 500 or e["status"] in (400, 403, 401):
            s["errors"] += 1
        if e["status"] == 404:
            s["not_found"] += 1
        is_auth = e["method"] in ("POST", "PUT") and auth_re.search(e["path"])
        if is_auth and e["status"] in (401, 403, 400, 429):
            s["auth_fail"] += 1
    return stats


def detect(entries, opts=None, auth_re=DEFAULT_AUTH_RE):
    opts = {**DEFAULTS, **(opts or {})}
    stats = aggregate(entries, auth_re)
    findings = []
    for ip, s in stats.items():
        if s["auth_fail"] >= opts["auth_fail_threshold"]:
            findings.append({"ip": ip, "type": "credential_stuffing", "severity": "high",
                             "count": s["auth_fail"],
                             "detail": "%d failed auth attempts" % s["auth_fail"]})
        if s["not_found"] >= opts["notfound_threshold"]:
            findings.append({"ip": ip, "type": "enumeration", "severity": "medium",
                             "count": s["not_found"],
                             "detail": "%d 404s across %d unique paths" % (s["not_found"], len(s["paths"]))})
        scanner_uas = [ua for ua in s["uas"] if SCANNER_UA_RE.search(ua)]
        if scanner_uas:
            findings.append({"ip": ip, "type": "scanner", "severity": "high",
                             "count": len(scanner_uas),
                             "detail": "scanner user-agent: %s" % scanner_uas[0]})
        if s["requests"] >= opts["min_requests_for_rate"]:
            rate = s["errors"] / s["requests"]
            if rate >= opts["error_rate_threshold"]:
                findings.append({"ip": ip, "type": "high_error_rate", "severity": "low",
                                 "count": s["errors"],
                                 "detail": "%.0f%% error responses over %d requests" % (rate * 100, s["requests"])})
    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["count"]), reverse=True)
    return findings


def blocklist(findings, min_severity="high"):
    floor = SEVERITY_RANK[min_severity]
    return sorted({f["ip"] for f in findings if SEVERITY_RANK[f["severity"]] >= floor})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Detect web abuse patterns in access logs.")
    parser.add_argument("logfile", help="access log in Common/Combined Log Format ('-' for stdin)")
    parser.add_argument("--json", dest="json_out", help="write findings to this JSON file")
    parser.add_argument("--blocklist", help="write suggested blocklist IPs to this file")
    parser.add_argument("--auth-fail-threshold", type=int, default=DEFAULTS["auth_fail_threshold"])
    parser.add_argument("--notfound-threshold", type=int, default=DEFAULTS["notfound_threshold"])
    args = parser.parse_args(argv)

    fh = sys.stdin if args.logfile == "-" else open(args.logfile, encoding="utf-8", errors="replace")
    parsed, skipped = [], 0
    try:
        for line in fh:
            entry = parse_line(line)
            if entry:
                parsed.append(entry)
            elif line.strip():
                skipped += 1
    finally:
        if fh is not sys.stdin:
            fh.close()

    opts = {"auth_fail_threshold": args.auth_fail_threshold,
            "notfound_threshold": args.notfound_threshold}
    findings = detect(parsed, opts)
    block = blocklist(findings)

    for f in findings:
        sys.stdout.write("[%-8s] %-15s %-18s %s\n" % (
            f["severity"].upper(), f["ip"], f["type"], f["detail"]))
    sys.stderr.write("\n%d lines parsed, %d unparseable | %d findings | %d IPs to block\n" % (
        len(parsed), skipped, len(findings), len(block)))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as out:
            json.dump(findings, out, indent=2)
    if args.blocklist:
        with open(args.blocklist, "w", encoding="utf-8") as out:
            out.write("\n".join(block) + ("\n" if block else ""))

    return 1 if block else 0


if __name__ == "__main__":
    raise SystemExit(main())
