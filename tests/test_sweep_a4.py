"""ITEM-4 regression: a non-numeric dst_port must be an error, not a silent match
against the events that have no port at all."""
import json

from conftest import SAMPLES
from bluecell.ingest import ingest_path
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.agents import AgentContext
from bluecell.agents.toolbox import Blackboard, SecurityToolbox


def _box(tmp_path):
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    ctx = AgentContext(events=events, incidents=correlate(events, window_minutes=120),
                       iocs=extract_iocs(events), digest=compress(events))
    return ctx, SecurityToolbox(ctx, "t", "Tester", Blackboard(str(tmp_path / "b.jsonl")))


def test_non_numeric_dst_port_is_error(tmp_path):
    ctx, box = _box(tmp_path)
    res = json.loads(box.call("search_events", {"dst_port": "abc"}))
    assert "error" in res and "dst_port" in res["error"], res
    assert "matches" not in res


def test_numeric_dst_port_still_filters(tmp_path):
    ctx, box = _box(tmp_path)
    port = next(e.dst_port for e in ctx.events if e.dst_port is not None)
    res = json.loads(box.call("search_events", {"dst_port": str(port)}))
    assert res["matches"] == sum(1 for e in ctx.events if e.dst_port == port)
    assert res["matches"] >= 1
