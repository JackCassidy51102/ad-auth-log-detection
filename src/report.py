"""Render events and findings into a readable text report."""
from __future__ import annotations

from collections import Counter

from .detections import Finding
from .events import NormalisedEvent


def summarise(events: list[NormalisedEvent]) -> str:
    total = len(events)
    failures = sum(1 for e in events if e.is_failure)
    successes = sum(1 for e in events if e.is_success)
    privileged = sum(1 for e in events if e.is_privileged)
    top_failed = Counter(e.account for e in events if e.is_failure and e.account).most_common(5)
    top_src = Counter(e.source_ip for e in events if e.is_failure and e.source_ip).most_common(5)

    lines = [
        "ACTIVE DIRECTORY AUTHENTICATION ANALYSIS",
        "=" * 42,
        f"Total events analysed : {total}",
        f"Failed logons  (4625) : {failures}",
        f"Successful     (4624) : {successes}",
        f"Privileged     (4672) : {privileged}",
        "",
        "TOP ACCOUNTS BY FAILED LOGON",
        "-" * 42,
    ]
    lines += [f"  {acct:<30} {n}" for acct, n in top_failed] or ["  (none)"]
    lines += ["", "TOP SOURCE IPS BY FAILED LOGON", "-" * 42]
    lines += [f"  {ip:<30} {n}" for ip, n in top_src] or ["  (none)"]
    return "\n".join(lines)


def render_findings(findings: list[Finding]) -> str:
    if not findings:
        return "\nDETECTIONS\n" + "-" * 42 + "\n  No detections triggered."
    order = {"critical": 0, "high": 1, "info": 2}
    findings = sorted(findings, key=lambda f: order.get(f.severity, 9))
    lines = ["", "DETECTIONS", "-" * 42]
    for f in findings:
        lines.append(f"  [{f.severity.upper():<8}] {f.rule:<22} {f.detail}")
    return "\n".join(lines)


def build_report(events: list[NormalisedEvent], findings: list[Finding]) -> str:
    return summarise(events) + "\n" + render_findings(findings) + "\n"
