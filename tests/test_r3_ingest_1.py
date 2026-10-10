"""BUG-R3-INGEST-1: loopback/unspecified IPs must not link unrelated hosts into one incident."""
from datetime import datetime, timedelta, timezone

import pytest

from bastion.models import Event
from bastion.pipeline.correlate import correlate

TS = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)


def _ev(host, user, ip, minutes=0):
    return Event(ts=TS + timedelta(minutes=minutes), source="edr", category="auth",
                 action="LogonFailed", message="m", host=host, user=user, src_ip=ip)


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "0.0.0.0", "::", "169.254.10.20"])
def test_non_routable_ip_does_not_merge_hosts(ip):
    events = [_ev("wks-a", "alice", ip), _ev("srv-b", "bob", ip, 1)]
    for inc in correlate(events):
        assert len(inc.hosts) == 1


def test_private_rfc1918_ip_still_links_hosts():
    events = [_ev("wks-a", "alice", "10.1.2.3"), _ev("srv-b", "bob", "10.1.2.3", 1)]
    incs = correlate(events)
    assert len(incs) == 1 and incs[0].hosts == {"wks-a", "srv-b"}
