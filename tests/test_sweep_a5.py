"""ITEM-5 regression: capped tool results must say how many items exist, and an
unknown IOC kind must be an error that lists the valid kinds, not a silent {}."""
import json

from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
import tempfile
from datetime import datetime, timedelta, timezone

from bastion.models import Event
from bastion.agents.base import AgentContext
from bastion.agents.toolbox import SecurityToolbox, Blackboard
from bastion.pipeline import extract_iocs
from bastion.pipeline.correlate import Incident

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _box(n=300):
    evs = [Event(ts=T0 + timedelta(seconds=i), source="edr", category="process",
                 action="proc_start", message=f"proc {i}", host="h1", user="bob",
                 process=f"p{i}.exe", src_ip="10.0.0.5", dst_ip=f"203.0.113.{i % 250}")
           for i in range(n)]
    for e in evs:
        e.attack.append("T1059")
    ctx = AgentContext(events=evs, incidents=[Incident(id="INC-1", events=list(evs))],
                       iocs=extract_iocs(evs), digest="", backbone=None)
    box = SecurityToolbox(ctx, "t", "T", Blackboard(tempfile.mktemp()))
    return ctx, box


def test_attack_lookup_reports_total_tagged():
    _, box = _box()
    r = json.loads(box.call("attack_lookup", {"technique_id": "T1059"}))
    assert len(r["tagged_events"]) == 25
    assert r["total"] == 300


def test_get_incident_reports_total_events():
    _, box = _box()
    r = json.loads(box.call("get_incident", {"incident_id": "INC-1"}))
    assert r["truncated"] is True
    assert r["total"] == 300


def test_list_iocs_reports_totals_per_kind():
    _, box = _box()
    r = json.loads(box.call("list_iocs", {"kind": "process"}))
    assert len(r["process"]) == 50
    assert r["total"]["process"] == 300


def test_list_iocs_kind_is_case_insensitive():
    _, box = _box()
    r = json.loads(box.call("list_iocs", {"kind": "PROCESS"}))
    assert len(r["process"]) == 50


def test_list_iocs_unknown_kind_is_error_with_valid_kinds():
    ctx, box = _box()
    r = json.loads(box.call("list_iocs", {"kind": "IP-typo"}))
    assert "error" in r
    for k in ctx.iocs:
        assert k in r["error"]
