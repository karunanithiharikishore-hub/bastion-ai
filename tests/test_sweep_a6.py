# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""ITEM-6 regression: a parent ATT&CK id (T1059) must be grounded by a
sub-technique tagged on the evidence (T1059.001), in attack_lookup,
submit_finding and the grounding check. A sibling (T1059.003) must not."""
import datetime as dt
import json
import tempfile

from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from bluecell.agents.base import AgentContext
from bluecell.agents.grounding import check_text, evidence_index, technique_matches
from bluecell.agents.toolbox import Blackboard, SecurityToolbox, BASE_TOOLS
from bluecell.models import Event
from bluecell.pipeline.correlate import Incident


def _events():
    base = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    evs = [Event(ts=base + dt.timedelta(seconds=i), source="edr", category="process",
                 action="proc_start", message=f"proc {i}", host="h0", user="bob",
                 process=f"p{i}.exe", src_ip="10.0.0.5", dst_ip="203.0.113.7")
           for i in range(2)]
    for e in evs:
        e.attack.append("T1059.001")
    return evs


def _box(evs):
    ctx = AgentContext(events=evs, incidents=[Incident(id="INC-1", events=list(evs))],
                       iocs={}, digest="", backbone=None)
    return SecurityToolbox(ctx, "t", "T", Blackboard(tempfile.mktemp()),
                           tools=BASE_TOOLS + ("submit_verdict",))


def test_technique_matches_parent_and_child_only():
    assert technique_matches("T1059", "T1059.001")
    assert technique_matches("t1059.001", "T1059.001")
    assert not technique_matches("T1059.003", "T1059.001")
    assert not technique_matches("T1059.001", "T1059")


def test_grounding_accepts_parent_of_tagged_subtechnique():
    idx = evidence_index(_events(), ["T1059.001"])
    assert check_text("Command execution via T1059 observed.", idx)["ok"]
    assert not check_text("Command execution via T1059.003 observed.", idx)["ok"]


def test_attack_lookup_lists_events_for_parent_id():
    r = json.loads(_box(_events()).call("attack_lookup", {"technique_id": "T1059"}))
    assert r["total"] == 2


def test_submit_finding_accepts_parent_technique_of_cited_subtechnique():
    evs = _events()
    box = _box(evs)
    res = json.loads(box.call("submit_finding", {
        "title": "p", "severity": "low", "confidence": 0.5,
        "rationale": "ran p0.exe", "evidence": [evs[0].event_id],
        "attack": ["T1059"]}))
    assert "error" not in res, res


def test_submit_finding_rejects_sibling_technique():
    evs = _events()
    box = _box(evs)
    res = json.loads(box.call("submit_finding", {
        "title": "p", "severity": "low", "confidence": 0.5,
        "rationale": "ran p0.exe", "evidence": [evs[0].event_id],
        "attack": ["T1059.003"]}))
    assert res.get("error") == "finding rejected", res
