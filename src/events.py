"""Normalised authentication event model.

A `NormalisedEvent` is the common shape the detection rules operate on, regardless of
whether the source was a real Windows Security ``.evtx`` file (see ``evtx_parser.py``) or
synthetic test data (see ``sample_data/generate_synthetic.py``). Keeping detection logic
decoupled from the EVTX format is what makes the rules unit-testable without committing any
real event logs.

Relevant Windows Security Event IDs:
    4624 - An account was successfully logged on
    4625 - An account failed to log on
    4672 - Special privileges assigned to new logon (privileged logon)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# Logon type reference (subset), used only for human-readable reporting.
LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}


@dataclass
class NormalisedEvent:
    """A single normalised authentication event."""

    event_id: int
    timestamp: datetime
    username: Optional[str] = None
    domain: Optional[str] = None
    source_ip: Optional[str] = None
    logon_type: Optional[int] = None
    auth_package: Optional[str] = None
    extra: dict = field(default_factory=dict)

    @property
    def is_failure(self) -> bool:
        return self.event_id == 4625

    @property
    def is_success(self) -> bool:
        return self.event_id == 4624

    @property
    def is_privileged(self) -> bool:
        return self.event_id == 4672

    @property
    def account(self) -> str:
        """Domain-qualified account key used for grouping (lower-cased)."""
        u = (self.username or "").lower()
        d = (self.domain or "").lower()
        return f"{d}\\{u}" if d else u

    def logon_type_name(self) -> str:
        if self.logon_type is None:
            return "-"
        return LOGON_TYPES.get(self.logon_type, str(self.logon_type))
