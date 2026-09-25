"""Detection rules over normalised authentication events.

All rules are pure functions of a list of :class:`~src.events.NormalisedEvent` plus explicit,
configurable thresholds. They return plain dataclass findings so they are trivial to unit
test and to render into a report.

Implemented detections:
    * brute_force            - many failures (4625) against a single account
    * password_spray         - one source IP failing against many distinct accounts
    * success_after_failures - a 4624 success shortly after >= N failures for an account
    * privileged_logons      - 4672 special-privilege logons (surface for review)

These reflect the analysis actually demonstrated by the project (failed/successful logon
summaries from Windows Security logs). They are intentionally simple, transparent rules -
not an ML model and not a SIEM.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from .events import NormalisedEvent


@dataclass
class Finding:
    rule: str
    severity: str
    entity: str
    count: int
    detail: str


def _sorted(events: Iterable[NormalisedEvent]) -> list[NormalisedEvent]:
    return sorted(events, key=lambda e: e.timestamp)


def brute_force(events: Iterable[NormalisedEvent], threshold: int = 5) -> list[Finding]:
    """Accounts with >= ``threshold`` failed logons (4625)."""
    if threshold < 1:
        raise ValueError("threshold must be >= 1")
    counts: dict[str, int] = {}
    for e in events:
        if e.is_failure and e.account:
            counts[e.account] = counts.get(e.account, 0) + 1
    findings = []
    for account, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        if n >= threshold:
            findings.append(
                Finding("brute_force", "high", account, n,
                        f"{n} failed logons (4625) for account {account}")
            )
    return findings


def password_spray(events: Iterable[NormalisedEvent],
                   distinct_accounts: int = 5) -> list[Finding]:
    """Source IPs that failed against >= ``distinct_accounts`` distinct accounts.

    Password spraying is characterised by *few* attempts against *many* accounts from one
    origin - the inverse shape of brute force.
    """
    if distinct_accounts < 1:
        raise ValueError("distinct_accounts must be >= 1")
    by_ip: dict[str, set[str]] = {}
    for e in events:
        if e.is_failure and e.source_ip and e.account:
            by_ip.setdefault(e.source_ip, set()).add(e.account)
    findings = []
    for ip, accounts in sorted(by_ip.items(), key=lambda kv: -len(kv[1])):
        if len(accounts) >= distinct_accounts:
            findings.append(
                Finding("password_spray", "high", ip, len(accounts),
                        f"source {ip} failed against {len(accounts)} distinct accounts")
            )
    return findings


def success_after_failures(events: Iterable[NormalisedEvent],
                           min_failures: int = 3,
                           window_minutes: int = 10) -> list[Finding]:
    """A successful logon (4624) preceded by >= ``min_failures`` failures for the same
    account within ``window_minutes`` - a possible successful brute force / spray."""
    if min_failures < 1:
        raise ValueError("min_failures must be >= 1")
    window = timedelta(minutes=window_minutes)
    by_account: dict[str, list[NormalisedEvent]] = {}
    for e in events:
        if e.account and (e.is_failure or e.is_success):
            by_account.setdefault(e.account, []).append(e)

    findings = []
    for account, evs in by_account.items():
        evs = _sorted(evs)
        for i, e in enumerate(evs):
            if not e.is_success:
                continue
            recent_failures = [
                p for p in evs[:i]
                if p.is_failure and (e.timestamp - p.timestamp) <= window
            ]
            if len(recent_failures) >= min_failures:
                findings.append(
                    Finding("success_after_failures", "critical", account,
                            len(recent_failures),
                            f"success for {account} after {len(recent_failures)} "
                            f"failures within {window_minutes}m")
                )
                break  # one finding per account is enough
    return findings


def privileged_logons(events: Iterable[NormalisedEvent]) -> list[Finding]:
    """Surface privileged logons (4672) for analyst review."""
    counts: dict[str, int] = {}
    for e in events:
        if e.is_privileged and e.account:
            counts[e.account] = counts.get(e.account, 0) + 1
    return [
        Finding("privileged_logon", "info", account, n,
                f"{n} privileged logon(s) (4672) for {account}")
        for account, n in sorted(counts.items(), key=lambda kv: -kv[1])
    ]


def run_all(events, config: dict | None = None) -> list[Finding]:
    cfg = config or {}
    findings: list[Finding] = []
    findings += brute_force(events, cfg.get("brute_force_threshold", 5))
    findings += password_spray(events, cfg.get("spray_distinct_accounts", 5))
    findings += success_after_failures(
        events,
        cfg.get("success_after_min_failures", 3),
        cfg.get("success_after_window_minutes", 10),
    )
    findings += privileged_logons(events)
    return findings
