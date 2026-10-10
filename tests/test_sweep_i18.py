"""ITEM-18: hub entities (public resolvers, root, many-host IPs) must not merge unrelated hosts."""
from datetime import datetime, timedelta

from bluecell.models import Event
from bluecell.pipeline.correlate import correlate


def _ev(i, host, **kw):
    return Event(ts=datetime(2026, 10, 3, 22, 0) + timedelta(minutes=i), source="t", category="network",
                 action=kw.pop("action", "x"), message=f"m{i}", host=host, **kw)


def _hosts(incs):
    return [i.hosts for i in incs]


def test_public_resolver_does_not_merge_hosts():
    evs = [_ev(i, f"wks{i}", dst_ip="8.8.8.8", action="allow") for i in range(5)]
    assert all(len(h) == 1 for h in _hosts(correlate(evs, min_events=1)))


def test_root_user_does_not_merge_hosts():
    evs = [_ev(i, f"srv{i}", user="root", action="login_failed") for i in range(5)]
    assert all(len(h) == 1 for h in _hosts(correlate(evs, min_events=1)))


def test_unlisted_hub_ip_by_degree_but_small_ip_still_links():
    evs = [_ev(i, f"h{i}", dst_ip="10.9.9.9") for i in range(6)]
    assert all(len(h) == 1 for h in _hosts(correlate(evs, min_events=1)))
    evs = [_ev(0, "a", src_ip="203.0.113.5"), _ev(1, "b", dst_ip="203.0.113.5")]
    assert len(correlate(evs, min_events=1)) == 1


def test_public_attacker_ip_across_hosts_links_one_incident():
    evs = [_ev(i, f"srv{i}", src_ip="185.220.101.7", action="login_failed") for i in range(5)]
    incs = correlate(evs)
    assert len(incs) == 1 and len(incs[0].hosts) == 5
