"""Generate a synthetic set of normalised authentication events.

This produces *fabricated* events purely to exercise the detection rules and to provide a
committed, non-sensitive example dataset. It contains NO real usernames, IPs, or captured
logs. It deliberately embeds three attack shapes plus benign noise:

    1. Brute force      - many 4625 failures against one account (bob)
    2. Password spray   - one source IP failing once against many accounts
    3. Success-after-failures - failures then a 4624 success for one account (carol)
    4. Privileged logon - a 4672 for an admin account
    5. Benign traffic   - ordinary successful network logons
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta

BASE = datetime(2026, 3, 10, 13, 0, 0)
DOMAIN = "corp.local"


def _ev(offset_s, event_id, user, ip, logon_type=3, pkg="NTLM"):
    return {
        "event_id": event_id,
        "timestamp": (BASE + timedelta(seconds=offset_s)).isoformat(),
        "username": user,
        "domain": DOMAIN,
        "source_ip": ip,
        "logon_type": logon_type,
        "auth_package": pkg,
    }


def build() -> list[dict]:
    events: list[dict] = []
    t = 0

    # 1. Brute force: 8 failures against 'bob' from a single host
    for _ in range(8):
        events.append(_ev(t, 4625, "bob", "10.0.0.66")); t += 5

    # 2. Password spray: 10.0.0.99 tries one password across 6 accounts (1 failure each)
    for user in ["alice", "bob", "carol", "dave", "erin", "frank"]:
        events.append(_ev(t, 4625, user, "10.0.0.99")); t += 3

    # 3. Success after failures: 4 failures then a success for 'carol'
    for _ in range(4):
        events.append(_ev(t, 4625, "carol", "10.0.0.50")); t += 10
    events.append(_ev(t, 4624, "carol", "10.0.0.50")); t += 10

    # 4. Privileged logon for an admin account
    events.append(_ev(t, 4672, "svc-admin", "10.0.0.10", logon_type=2, pkg="Kerberos")); t += 5

    # 5. Benign successful logons
    for user in ["alice", "dave", "erin"]:
        events.append(_ev(t, 4624, user, "10.0.0.20", pkg="Kerberos")); t += 30

    return events


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "synthetic_events.json")
    events = build()
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(events, fh, indent=2)
    print(f"Wrote {len(events)} synthetic events to {out}")


if __name__ == "__main__":
    main()
