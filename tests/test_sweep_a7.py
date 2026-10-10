"""ITEM-7 regression: aggregate's action filter must match like search_events (any case,
substring), and group_by must accept dst_port so port scans can be counted."""
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
                 action="LOGIN_FAILED" if i % 2 else "conn_allow", message=f"m{i}",
                 host="h1", src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=22 if i < 6 else 443)
           for i in range(10)]
    ctx = AgentContext(events=evs, incidents=[], iocs=extract_iocs(evs), digest="", backbone=None)
    return SecurityToolbox(ctx, "t", "T", Blackboard(tempfile.mktemp()))


def test_aggregate_action_filter_matches_search_events_semantics():
    box = _box()
    search = json.loads(box.call("search_events", {"action": "LOGIN_FAILED", "limit": 200}))["matches"]
    assert search == 5
    assert json.loads(box.call("aggregate", {"group_by": "host", "action": "LOGIN_FAILED"}))["total"] == search
    assert json.loads(box.call("aggregate", {"group_by": "host", "action": "login_failed"}))["total"] == search
    assert json.loads(box.call("aggregate", {"group_by": "host", "action": "LOGIN"}))["total"] == search


def test_aggregate_group_by_dst_port_counts_ports():
    box = _box()
    r = json.loads(box.call("aggregate", {"group_by": "dst_port"}))
    assert "error" not in r
    assert r["total"] == 10
    assert r["distinct"] == 2
