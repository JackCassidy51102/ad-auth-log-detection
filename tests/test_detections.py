"""Unit tests for the detection rules, using small synthetic event sets."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from src.detections import (
    brute_force,
    password_spray,
    success_after_failures,
    privileged_logons,
    run_all,
)
from src.events import NormalisedEvent

BASE = datetime(2026, 3, 10, 12, 0, 0)


def ev(sec, event_id, user, ip="10.0.0.1", domain="corp.local"):
    return NormalisedEvent(
        event_id=event_id,
        timestamp=BASE + timedelta(seconds=sec),
        username=user,
        domain=domain,
        source_ip=ip,
    )


def test_brute_force_triggers_at_threshold():
    events = [ev(i, 4625, "bob") for i in range(5)]
    findings = brute_force(events, threshold=5)
    assert len(findings) == 1
    assert findings[0].entity == "corp.local\\bob"
    assert findings[0].count == 5


def test_brute_force_below_threshold_is_silent():
    events = [ev(i, 4625, "bob") for i in range(4)]
    assert brute_force(events, threshold=5) == []


def test_brute_force_ignores_successes():
    events = [ev(i, 4624, "bob") for i in range(10)]
    assert brute_force(events, threshold=5) == []


def test_password_spray_counts_distinct_accounts_per_ip():
    events = [ev(i, 4625, u, ip="10.0.0.99")
              for i, u in enumerate(["a", "b", "c", "d", "e"])]
    findings = password_spray(events, distinct_accounts=5)
    assert len(findings) == 1
    assert findings[0].entity == "10.0.0.99"
    assert findings[0].count == 5


def test_password_spray_same_account_repeated_is_not_spray():
    events = [ev(i, 4625, "a", ip="10.0.0.99") for i in range(10)]
    assert password_spray(events, distinct_accounts=5) == []


def test_success_after_failures_within_window():
    events = [ev(i * 10, 4625, "carol") for i in range(3)]
    events.append(ev(60, 4624, "carol"))
    findings = success_after_failures(events, min_failures=3, window_minutes=10)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_success_after_failures_outside_window_is_silent():
    events = [ev(0, 4625, "carol"), ev(1, 4625, "carol"), ev(2, 4625, "carol")]
    events.append(ev(60 * 60, 4624, "carol"))  # 1 hour later
    assert success_after_failures(events, min_failures=3, window_minutes=10) == []


def test_privileged_logons_surfaced():
    events = [ev(0, 4672, "svc-admin")]
    findings = privileged_logons(events)
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_invalid_threshold_raises():
    with pytest.raises(ValueError):
        brute_force([], threshold=0)


def test_run_all_combines_rules():
    events = [ev(i, 4625, "bob") for i in range(6)]
    findings = run_all(events)
    assert any(f.rule == "brute_force" for f in findings)
