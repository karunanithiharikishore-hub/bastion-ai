# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-13 regression: notes must not evict findings/verdicts from read_board,
and a single agent's notes are capped in count and length. Offline, no model."""
import json

from conftest import SAMPLES
from bastion.ingest import ingest_path
from bastion.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bastion.agents import AgentContext
from bastion.agents.toolbox import Blackboard, SecurityToolbox


def _box(tmp_path):
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    ctx = AgentContext(events=events, incidents=correlate(events, window_minutes=120),
                       iocs=extract_iocs(events), digest=compress(events))
    return SecurityToolbox(ctx, "t", "Tester", Blackboard(str(tmp_path / "b.jsonl")))


def test_findings_survive_a_flood_of_notes(tmp_path):
    box = _box(tmp_path)
    box.board.post({"kind": "finding", "agent": "other", "role": "x", "title": "Real finding"})
    for i in range(70):
        box.call("post_note", {"message": f"noise {i}"})
    r = json.loads(box.call("read_board", {}))
    assert any(e["kind"] == "finding" for e in r["entries"])


def test_notes_per_agent_are_capped(tmp_path):
    box = _box(tmp_path)
    for i in range(70):
        box.call("post_note", {"message": f"noise {i}"})
    assert len(box.board.read()) <= 10


def test_note_length_is_capped(tmp_path):
    box = _box(tmp_path)
    box.call("post_note", {"message": "a" * 2000})
    assert len(box.board.read()[0]["message"]) <= 500
