"""ITEM-9 regression: search_events `ip` must canonicalise the query the way the parsers store
addresses, so expanded IPv6, zero-padded IPv4 and stray whitespace still match."""
import json
import tempfile
from datetime import datetime, timedelta, timezone

from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from bluecell.models import Event
from bluecell.agents.base import AgentContext
from bluecell.agents.toolbox import SecurityToolbox, Blackboard
from bluecell.pipeline import extract_iocs

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _box():
    evs = [Event(ts=T0 + timedelta(seconds=i), source="fw", category="network",
                 action="allow", message=f"conn {i}", host=f"h{i}", user="bob",
                 src_ip="2001:db8::1", dst_ip="203.0.113.9") for i in range(3)]
    ctx = AgentContext(events=evs, incidents=[], iocs=extract_iocs(evs), digest="", backbone=None)
    return SecurityToolbox(ctx, "t", "T", Blackboard(tempfile.mktemp()))


def _matches(box, ip):
    return json.loads(box.call("search_events", {"ip": ip}))["matches"]


def test_ip_query_expanded_ipv6_matches():
    assert _matches(_box(), "2001:0db8:0:0:0:0:0:1") == 3


def test_ip_query_zero_padded_ipv4_matches():
    assert _matches(_box(), "203.0.113.009") == 3


def test_ip_query_trailing_whitespace_matches():
    assert _matches(_box(), "203.0.113.9 ") == 3


def test_ip_query_uppercase_ipv6_matches():
    assert _matches(_box(), "2001:DB8::1") == 3
