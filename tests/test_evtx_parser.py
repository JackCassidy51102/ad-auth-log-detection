"""Tests for the EVTX XML->NormalisedEvent mapping.

These exercise the field mapping using representative Windows Security event XML, so the
parser logic is validated without needing python-evtx or a real .evtx file.
"""
from __future__ import annotations

from src.evtx_parser import _parse_record_xml

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'

FAILED_4625 = f"""<Event {NS}>
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-03-10T13:44:20.123456Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">bob</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="IpAddress">10.0.0.66</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
  </EventData>
</Event>"""

SUCCESS_4624 = f"""<Event {NS}>
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-03-10T13:45:00Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">carol</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="IpAddress">10.0.0.50</Data>
    <Data Name="LogonType">10</Data>
  </EventData>
</Event>"""

UNRELATED = f"""<Event {NS}>
  <System><EventID>4104</EventID><TimeCreated SystemTime="2026-03-10T13:45:00Z"/></System>
  <EventData></EventData>
</Event>"""


def test_parse_failed_logon_fields():
    ev = _parse_record_xml(FAILED_4625)
    assert ev is not None
    assert ev.event_id == 4625 and ev.is_failure
    assert ev.username == "bob"
    assert ev.domain == "CORP"
    assert ev.source_ip == "10.0.0.66"
    assert ev.logon_type == 3
    assert ev.auth_package == "NTLM"
    assert ev.account == "corp\\bob"


def test_parse_success_logon_type_name():
    ev = _parse_record_xml(SUCCESS_4624)
    assert ev.is_success
    assert ev.logon_type_name() == "RemoteInteractive"


def test_unrelated_event_ignored():
    assert _parse_record_xml(UNRELATED) is None
