#!/usr/bin/env python3
"""Offline analytics over the honeypot's JSON session logs.

Usage:
    python3 analyze_logs.py [--logs-dir logs] [--csv-out report.csv]
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import statistics
from collections import Counter
from datetime import datetime
from typing import Dict, List


def load_sessions(logs_dir: str) -> List[dict]:
    sessions = []
    for path in glob.glob(f"{logs_dir}/session_*.json"):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                sessions.append(json.load(fh))
        except Exception as exc:
            print(f"warning: could not read {path}: {exc}")
    return sessions


def parse_ts(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


def top_commands(sessions: List[dict], n: int = 20) -> Counter:
    counter: Counter = Counter()
    for s in sessions:
        for c in s.get("commands", []):
            cmd = (c.get("command") or "").split()
            if cmd:
                counter[cmd[0]] += 1
    return Counter(dict(counter.most_common(n)))


def top_credentials(sessions: List[dict], n: int = 20):
    users, pwds, pairs = Counter(), Counter(), Counter()
    for s in sessions:
        for a in s.get("auth_attempts", []):
            users[a.get("username", "")] += 1
            pwds[a.get("password", "")] += 1
            pairs[(a.get("username", ""), a.get("password", ""))] += 1
    return (Counter(dict(users.most_common(n))),
            Counter(dict(pwds.most_common(n))),
            Counter(dict(pairs.most_common(n))))


def top_countries(sessions: List[dict], n: int = 20) -> Counter:
    return Counter(dict(Counter(s.get("geo_country", "unknown") for s in sessions).most_common(n)))


def top_isps(sessions: List[dict], n: int = 20) -> Counter:
    return Counter(dict(Counter(s.get("geo_isp", "unknown") for s in sessions).most_common(n)))


def most_active_hour(sessions: List[dict]) -> Dict[int, int]:
    hours = Counter()
    for s in sessions:
        dt = parse_ts(s.get("start_time", ""))
        if dt:
            hours[dt.hour] += 1
    return dict(sorted(hours.items()))


def average_session_duration(sessions: List[dict]):
    durations = [s["duration_seconds"] for s in sessions if s.get("duration_seconds") is not None]
    if not durations:
        return None
    return {
        "mean": round(statistics.mean(durations), 2),
        "median": round(statistics.median(durations), 2),
        "max": round(max(durations), 2),
        "min": round(min(durations), 2),
    }


def command_frequency_table(sessions: List[dict]) -> Dict[str, int]:
    counter: Counter = Counter()
    for s in sessions:
        for c in s.get("commands", []):
            if c.get("command"):
                counter[c["command"]] += 1
    return dict(counter)


def print_report(sessions: List[dict]):
    print("=" * 70)
    print(f" SSH HONEYPOT ANALYTICS — {len(sessions)} session(s) analyzed")
    print("=" * 70)

    print("\n-- Top commands --")
    for cmd, count in top_commands(sessions).items():
        print(f"  {count:>5}  {cmd}")

    users, pwds, pairs = top_credentials(sessions)
    print("\n-- Top usernames --")
    for u, count in users.items():
        print(f"  {count:>5}  {u!r}")

    print("\n-- Top passwords --")
    for p, count in pwds.items():
        print(f"  {count:>5}  {p!r}")

    print("\n-- Top username:password pairs --")
    for (u, p), count in pairs.items():
        print(f"  {count:>5}  {u!r}:{p!r}")

    print("\n-- Top countries --")
    for country, count in top_countries(sessions).items():
        print(f"  {count:>5}  {country}")

    print("\n-- Top ISPs / ASNs --")
    for isp, count in top_isps(sessions).items():
        print(f"  {count:>5}  {isp}")

    print("\n-- Sessions by hour of day (UTC) --")
    for hour, count in most_active_hour(sessions).items():
        print(f"  {hour:02d}:00  {'#' * count} ({count})")

    dur_stats = average_session_duration(sessions)
    print("\n-- Session duration (seconds) --")
    if dur_stats:
        for k, v in dur_stats.items():
            print(f"  {k}: {v}")
    else:
        print("  no data")

    scanners = sum(1 for s in sessions if s.get("likely_scanner"))
    print(f"\n-- Likely scanner/tool sessions: {scanners} / {len(sessions)} --")


def export_csv(sessions: List[dict], path: str):
    fieldnames = [
        "session_id", "src_ip", "geo_country", "geo_city", "geo_asn", "geo_isp",
        "accepted_username", "accepted_password", "fingerprint_label",
        "likely_scanner", "start_time", "end_time", "duration_seconds",
        "num_commands", "num_failed_commands", "disconnect_reason",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for s in sessions:
            writer.writerow({
                "session_id": s.get("session_id"),
                "src_ip": s.get("src_ip"),
                "geo_country": s.get("geo_country"),
                "geo_city": s.get("geo_city"),
                "geo_asn": s.get("geo_asn"),
                "geo_isp": s.get("geo_isp"),
                "accepted_username": s.get("accepted_username"),
                "accepted_password": s.get("accepted_password"),
                "fingerprint_label": s.get("fingerprint_label"),
                "likely_scanner": s.get("likely_scanner"),
                "start_time": s.get("start_time"),
                "end_time": s.get("end_time"),
                "duration_seconds": s.get("duration_seconds"),
                "num_commands": len(s.get("commands", [])),
                "num_failed_commands": len(s.get("failed_commands", [])),
                "disconnect_reason": s.get("disconnect_reason"),
            })
    print(f"\nCSV report written to {path}")


def main():
    parser = argparse.ArgumentParser(description="Analyze SSH honeypot session logs")
    parser.add_argument("--logs-dir", default="logs", help="Directory containing session_*.json files")
    parser.add_argument("--csv-out", default=None, help="Optional path to also write a CSV summary")
    args = parser.parse_args()

    sessions = load_sessions(args.logs_dir)
    if not sessions:
        print(f"No session logs found in {args.logs_dir}/")
        return

    print_report(sessions)
    if args.csv_out:
        export_csv(sessions, args.csv_out)


if __name__ == "__main__":
    main()
