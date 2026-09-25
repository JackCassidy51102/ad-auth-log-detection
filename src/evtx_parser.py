"""Parse a Windows Security ``.evtx`` file into :class:`NormalisedEvent` objects.

This layer depends on the optional ``python-evtx`` package. It is deliberately thin: it maps
the relevant EventData fields for 4624/4625/4672 into the normalised model that the detection
rules consume. Keeping the mapping isolated here means the rules stay testable with synthetic
data and never need a real log file.

Note on validation: the detection logic in this project is unit-tested against synthetic
normalised events. This EVTX mapping follows the documented Windows Security event schema; it
should be validated end-to-end against a real Domain Controller ``Security.evtx`` before being
relied on operationally (see README "Status & limitations").
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterator
import xml.etree.ElementTree as ET

from .events import NormalisedEvent

RELEVANT_EVENT_IDS = {4624, 4625, 4672}

# XML namespace used by the Windows Event Log schema.
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _text(data: dict, *names: str):
    for n in names:
        v = data.get(n)
        if v not in (None, "", "-"):
            return v
    return None


def _parse_record_xml(xml_str: str) -> NormalisedEvent | None:
    """Convert one EVTX record's XML into a NormalisedEvent (or None if not relevant)."""
    root = ET.fromstring(xml_str)
    system = root.find("e:System", _NS)
    if system is None:
        return None
    eid_el = system.find("e:EventID", _NS)
    if eid_el is None or eid_el.text is None:
        return None
    event_id = int(eid_el.text)
    if event_id not in RELEVANT_EVENT_IDS:
        return None

    ts_el = system.find("e:TimeCreated", _NS)
    ts_raw = ts_el.get("SystemTime") if ts_el is not None else None
    timestamp = _parse_time(ts_raw)

    data = {}
    ed = root.find("e:EventData", _NS)
    if ed is not None:
        for d in ed.findall("e:Data", _NS):
            name = d.get("Name")
            if name:
                data[name] = d.text

    logon_type = _text(data, "LogonType")
    return NormalisedEvent(
        event_id=event_id,
        timestamp=timestamp,
        username=_text(data, "TargetUserName", "SubjectUserName"),
        domain=_text(data, "TargetDomainName", "SubjectDomainName"),
        source_ip=_text(data, "IpAddress"),
        logon_type=int(logon_type) if logon_type and logon_type.isdigit() else None,
        auth_package=_text(data, "AuthenticationPackageName", "LmPackageName"),
    )


def _parse_time(raw: str | None) -> datetime:
    if not raw:
        return datetime.min
    raw = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        # Trim sub-second precision Python can't parse, then retry.
        if "." in raw:
            head, _, tail = raw.partition(".")
            tz = ""
            for marker in ("+", "-"):
                if marker in tail:
                    tz = marker + tail.split(marker, 1)[1]
                    break
            return datetime.fromisoformat(head + tz)
        raise


def parse_evtx(path: str) -> Iterator[NormalisedEvent]:
    """Yield normalised 4624/4625/4672 events from a Security ``.evtx`` file.

    Requires ``python-evtx``. Install with ``pip install python-evtx`` (see requirements.txt).
    """
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError(
            "python-evtx is required to parse .evtx files. Install it with "
            "`pip install python-evtx`."
        ) from exc

    with Evtx(path) as log:
        for record in log.records():
            try:
                ev = _parse_record_xml(record.xml())
            except ET.ParseError:
                continue
            if ev is not None:
                yield ev
