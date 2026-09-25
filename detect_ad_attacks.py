#!/usr/bin/env python3
"""CLI entry point: parse Windows Security auth events and run detection rules.

Usage:
    # Against a real Domain Controller Security log (requires python-evtx):
    python detect_ad_attacks.py --evtx path/to/Security.evtx

    # Against synthetic normalised events (JSON), no python-evtx needed:
    python detect_ad_attacks.py --json sample_data/synthetic_events.json

Configuration (thresholds) can be overridden via CLI flags; see --help.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from src import detections, report
from src.events import NormalisedEvent


def load_json(path: str) -> list[NormalisedEvent]:
    with open(path, encoding="utf-8") as fh:
        rows = json.load(fh)
    events = []
    for r in rows:
        events.append(
            NormalisedEvent(
                event_id=int(r["event_id"]),
                timestamp=datetime.fromisoformat(r["timestamp"]),
                username=r.get("username"),
                domain=r.get("domain"),
                source_ip=r.get("source_ip"),
                logon_type=r.get("logon_type"),
                auth_package=r.get("auth_package"),
            )
        )
    return events


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="AD authentication-log attack detection")
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--evtx", help="Path to a Windows Security .evtx file")
    grp.add_argument("--json", help="Path to normalised events JSON")
    p.add_argument("--brute-force-threshold", type=int, default=5)
    p.add_argument("--spray-distinct-accounts", type=int, default=5)
    p.add_argument("--success-after-min-failures", type=int, default=3)
    p.add_argument("--success-after-window-minutes", type=int, default=10)
    p.add_argument("-o", "--output", help="Write report to file instead of stdout")
    args = p.parse_args(argv)

    if args.evtx:
        from src.evtx_parser import parse_evtx
        events = list(parse_evtx(args.evtx))
    else:
        events = load_json(args.json)

    config = {
        "brute_force_threshold": args.brute_force_threshold,
        "spray_distinct_accounts": args.spray_distinct_accounts,
        "success_after_min_failures": args.success_after_min_failures,
        "success_after_window_minutes": args.success_after_window_minutes,
    }
    findings = detections.run_all(events, config)
    text = report.build_report(events, findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Report written to {args.output} ({len(events)} events, {len(findings)} findings)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
