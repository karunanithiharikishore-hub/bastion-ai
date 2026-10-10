"""BUG-INGEST-4 follow-up: Event entity fields treat placeholders as None and drop control chars."""
from datetime import datetime, timezone

import pytest

from bastion.models import Event
from bastion.pipeline.correlate import correlate

TS = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ev(**kw):
    return Event(ts=TS, source="firewall", category="network", action="deny", message="m", **kw)


@pytest.mark.parametrize("placeholder", ["-", "N/A", "n/a", "null", "(null)", "none", "unknown", "?"])
def test_placeholder_entities_become_none(placeholder):
    e = _ev(host=placeholder, user=placeholder, domain=placeholder, process=placeholder)
    assert (e.host, e.user, e.domain, e.process) == (None, None, None, None)


def test_control_chars_stripped_from_entities():
    e = _ev(host="ho\x00st\x1f", user="\x00bob\x7f", domain="ex\x00ample.com")
    assert (e.host, e.user, e.domain) == ("host", "bob", "example.com")


def test_placeholder_after_control_strip_becomes_none():
    assert _ev(user="-\x00").user is None


def test_normal_values_untouched():
    e = _ev(host="WS-01", user="alice", domain="example.com", process="cmd.exe")
    assert (e.host, e.user, e.domain, e.process) == ("WS-01", "alice", "example.com", "cmd.exe")


def test_placeholder_hosts_do_not_link_unrelated_events():
    events = [_ev(host="-", user="N/A", dst_ip=f"10.0.0.{i}") for i in (1, 2, 3)]
    assert correlate(events) == []   # shared "-" used to merge these into one incident
