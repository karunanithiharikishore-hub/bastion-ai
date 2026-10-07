# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Autonomous Tier-3 agents: toolbox, grounding of submissions, MCP server,
and the tool-use loop (driven by a scripted fake model, so tests are offline)."""
import copy
import json
import os
import subprocess
import sys

from conftest import SAMPLES
from bluecell.ingest import ingest_path
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.agents import AgentContext, SwarmOrchestrator
from bluecell.agents.roles import (
    ThreatHunter, SecurityEngineer, JuniorSocAnalyst, SeniorSocAnalyst,
)
from bluecell.agents.runtime import SwarmSession
from bluecell.agents.toolbox import Blackboard, SecurityToolbox, file_slug

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


def _ctx(backbone=None):
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    return AgentContext(events=events, incidents=correlate(events, window_minutes=120),
                        iocs=extract_iocs(events), digest=compress(events),
                        backbone=backbone)


def _box(tmp_path, ctx=None):
    ctx = ctx or _ctx()
    return ctx, SecurityToolbox(ctx, "t", "Tester", Blackboard(str(tmp_path / "b.jsonl")))


def test_search_and_pivot_return_event_ids(tmp_path):
    ctx, box = _box(tmp_path)
    ip = next(e.src_ip for e in ctx.events if e.src_ip)
    res = json.loads(box.call("search_events", {"ip": ip}))
    assert res["matches"] >= 1
    assert res["events"][0].split()[0] in {e.event_id for e in ctx.events}
    piv = json.loads(box.call("pivot", {"value": ip}))
    assert piv["matches"] >= res["matches"]


def test_submit_finding_rejects_hallucinations(tmp_path):
    ctx, box = _box(tmp_path)
    res = json.loads(box.call("submit_finding", {
        "title": "Beacon to 9.9.9.9", "severity": "high", "confidence": 0.9,
        "rationale": "made up", "evidence": ["deadbeef0000"], "attack": ["T1003"]}))
    assert res["error"] == "finding rejected"
    text = " ".join(res["problems"])
    assert "unknown event_ids" in text and "T1003" in text and "9.9.9.9" in text
    assert box.findings == []


def test_submit_finding_accepts_grounded_and_posts_to_board(tmp_path):
    ctx, box = _box(tmp_path)
    e = next(e for e in ctx.events if e.attack)
    res = json.loads(box.call("submit_finding", {
        "title": "Grounded", "severity": "high", "confidence": 0.8,
        "rationale": f"seen on {e.host} via certutil.exe", "evidence": [e.event_id],
        "attack": [e.attack[0]]}))
    assert res["accepted"] is True
    assert box.findings[0]["evidence"] == [e.event_id]
    assert any(x["kind"] == "finding" for x in box.board.read())


def test_unknown_tool_and_bad_args_do_not_raise(tmp_path):
    _, box = _box(tmp_path)
    assert "unknown tool" in box.call("rm_rf", {})
    assert "bad arguments" in box.call("get_event", {"nope": 1})


def test_mcp_server_protocol(tmp_path):
    ctx = _ctx()
    session = SwarmSession(ctx, seed=[{"agent": "soc2-lead", "title": "x"}])
    try:
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "case_overview", "arguments": {}}},
        ]
        proc = subprocess.run(
            [sys.executable, "-m", "bluecell.agents.mcp_server", "--session", session.dir,
             "--agent", "Security Engineer / Architect", "--role", "r"],
            input="\n".join(map(json.dumps, msgs)) + "\n", capture_output=True,
            text=True, env=dict(os.environ, PYTHONPATH=SRC), timeout=60)
        replies = {r["id"]: r for r in map(json.loads, proc.stdout.splitlines())}
        assert set(replies) == {1, 2, 3}           # notification gets no reply
        assert replies[1]["result"]["serverInfo"]["name"] == "bluecell"
        names = {t["name"] for t in replies[2]["result"]["tools"]}
        assert {"search_events", "submit_finding", "read_board"} <= names
        overview = json.loads(replies[3]["result"]["content"][0]["text"])
        assert overview["earlier_tiers"][0]["agent"] == "soc2-lead"
        out = os.path.join(session.dir, file_slug("Security Engineer / Architect") + ".out.json")
        assert json.load(open(out))["calls"][0]["tool"] == "case_overview"
    finally:
        session.close()


class ScriptedModel:
    """Stands in for the API backbone: replays a fixed tool-use conversation."""
    resolved = "api"
    model = "fake"

    def __init__(self, script):
        self.script = list(script)
        self.seen = []

    def messages(self, body):
        self.seen.append(copy.deepcopy(body))
        return {"content": self.script.pop(0)}


def test_api_tool_loop_files_grounded_finding():
    ctx = _ctx()
    e = next(e for e in ctx.events if e.attack)
    model = ScriptedModel([
        [{"type": "tool_use", "id": "u1", "name": "search_events",
          "input": {"technique": e.attack[0]}}],
        [{"type": "tool_use", "id": "u2", "name": "submit_finding",
          "input": {"title": "bad", "severity": "high", "confidence": 0.5,
                    "rationale": "x", "evidence": ["nope"]}}],
        [{"type": "tool_use", "id": "u3", "name": "submit_finding",
          "input": {"title": "Fixed", "severity": "high", "confidence": 0.7,
                    "rationale": "grounded", "evidence": [e.event_id]}}],
        [{"type": "text", "text": "Done: one finding."}],
    ])
    ctx.backbone = model
    session = SwarmSession(ctx, seed=[])
    try:
        agent = ThreatHunter()
        findings = agent.run(ctx, use_llm=True, session=session)
    finally:
        session.close()
    assert [f.title for f in findings] == ["Fixed"]
    assert findings[0].origin == "agent"
    run = agent.last_run
    assert run["mode"] == "autonomous" and run["tool_calls"] == 3
    assert run["rejected_submissions"] == 1 and run["summary"] == "Done: one finding."
    # The rejection reason was fed back to the model as a tool error.
    feedback = model.seen[2]["messages"][-1]["content"][0]
    assert feedback["is_error"] is True and "unknown event_ids" in feedback["content"]


def test_agent_failure_falls_back_to_rules_and_says_so():
    class Broken(ScriptedModel):
        def messages(self, body):
            raise RuntimeError("backbone down")
    ctx = _ctx(Broken([]))
    session = SwarmSession(ctx, seed=[])
    try:
        agent = SecurityEngineer()
        findings = agent.run(ctx, use_llm=True, session=session)
    finally:
        session.close()
    assert findings and all(f.origin == "rules" for f in findings)
    assert agent.last_run["mode"] == "fallback (rules)"
    assert "backbone down" in agent.last_run["error"]


def test_orchestrator_reports_agent_runs_without_llm():
    out = SwarmOrchestrator(_ctx(), use_llm=False).run()
    assert len(out["agent_runs"]) == out["agent_count"]
    assert {r["tier"] for r in out["agent_runs"]} == {1, 2, 3}
    assert {r["mode"] for r in out["agent_runs"]} == {"rules"}
    assert out["counts"]["autonomous_agents"] == 0


def test_tier1_findings_must_cite_own_source(tmp_path):
    ctx = _ctx()
    sources = sorted({e.source for e in ctx.events})
    other = next(e for e in ctx.events if e.source != sources[0])
    box = SecurityToolbox(ctx, "soc1-x", "Tier-1", Blackboard(str(tmp_path / "b.jsonl")),
                          source_scope=sources[0])
    res = json.loads(box.call("submit_finding", {
        "title": "t", "severity": "low", "confidence": 0.5, "rationale": "r",
        "evidence": [other.event_id]}))
    assert "you triage the" in " ".join(res["problems"])


def test_submit_verdict_only_for_tier2_and_validated(tmp_path):
    ctx, box = _box(tmp_path)
    assert "unknown tool" in box.call("submit_verdict", {})   # not granted
    inc = ctx.incidents[0]
    seed = [{"id": "F-abc", "title": "cand"}]
    t2 = SecurityToolbox(ctx, "soc2-lead", "Tier-2", box.board, board_seed=seed,
                         tools=SeniorSocAnalyst.tools)
    bad = json.loads(t2.call("submit_verdict", {
        "incident_id": "INC-nope", "decision": "maybe", "confidence": 2,
        "rationale": "seen 9.9.9.9", "evidence": [], "reviewed_candidates": ["F-zzz"]}))
    text = " ".join(bad["problems"])
    for frag in ("unknown incident_id", "decision", "confidence", "F-zzz", "9.9.9.9"):
        assert frag in text
    ok = json.loads(t2.call("submit_verdict", {
        "incident_id": inc.id, "decision": "dismissed", "confidence": 0.7,
        "rationale": "benign", "evidence": [inc.events[0].event_id],
        "reviewed_candidates": ["F-abc"]}))
    assert ok["accepted"] and t2.verdicts[inc.id]["decision"] == "dismissed"


def test_tier2_agent_verdict_overrides_rules_and_marks_candidates():
    ctx = _ctx()
    inc = ctx.incidents[0]
    tier1 = JuniorSocAnalyst(inc.events[0].source).analyze(ctx)
    assert tier1
    model = ScriptedModel([
        [{"type": "tool_use", "id": "v", "name": "submit_verdict",
          "input": {"incident_id": inc.id, "decision": "dismissed", "confidence": 0.6,
                    "rationale": "admin maintenance window",
                    "evidence": [inc.events[0].event_id],
                    "reviewed_candidates": [tier1[0].id]}}],
        [{"type": "text", "text": "Dismissed."}],
    ])
    ctx.backbone = model
    session = SwarmSession(ctx, seed=SwarmOrchestrator._seed(tier1))
    try:
        senior = SeniorSocAnalyst(name="soc2-lead")
        verdicts = senior.verify(ctx, tier1, use_llm=True, session=session)
    finally:
        session.close()
    v = next(f for f in verdicts if f.incident_id == inc.id)
    assert v.origin == "agent" and v.status == "dismissed"
    assert v.rationale == "admin maintenance window"
    assert all(c.status == "dismissed" and "soc2-lead" in c.verified_by for c in tier1)
    assert senior.last_run["mode"] == "autonomous"


def test_full_swarm_runs_every_tier_as_agents():
    class Quiet(ScriptedModel):
        """Every agent looks, then concludes there is nothing to file."""
        def messages(self, body):
            if len(body["messages"]) == 1:
                return {"content": [{"type": "tool_use", "id": "o",
                                     "name": "case_overview", "input": {}}]}
            return {"content": [{"type": "text", "text": "nothing to file"}]}
    out = SwarmOrchestrator(_ctx(Quiet([]))).run()
    assert out["counts"]["autonomous_agents"] == out["agent_count"]
    assert {r["tier"] for r in out["agent_runs"]} == {1, 2, 3}
    # Nobody filed anything; the Tier-2 run record must say the incident went undecided.
    senior = next(r for r in out["agent_runs"] if r["tier"] == 2)
    assert "got no verdict" in senior["note"]


def test_benign_sample_is_a_real_false_positive_test_case():
    """samples_benign must look suspicious to the rules (an incident forms across
    every source), or it cannot test whether Tier-2 dismisses benign activity."""
    from conftest import BENIGN_SAMPLES
    events = normalize(ingest_path(BENIGN_SAMPLES))
    map_attack(events)
    assert {e.source for e in events} == {"auth", "dns", "edr", "firewall", "syslog"}
    incidents = correlate(events, window_minutes=60)
    assert len(incidents) == 1 and incidents[0].techniques
    # The change ticket the agents should find is in the evidence.
    assert any("CHG0042117" in e.message for e in events)


def test_headline_follows_tier2_agent_verdict():
    from bluecell.report.rca import apply_tier2_verdict
    rule = {"level": "likely-malicious", "confidence": 0.8, "headline": "Likely a real attack.",
            "why": "rules", "recommended_checks": ["isolate"]}
    dismissed = apply_tier2_verdict(rule, {"status": "dismissed", "confidence": 0.85,
                                           "rationale": "ticketed maintenance"})
    assert dismissed["level"] == "likely-benign" and dismissed["confidence"] == 0.85
    assert dismissed["why"] == "ticketed maintenance" and dismissed["overrides_rules"]
    assert dismissed["rule_verdict"]["level"] == "likely-malicious"
    confirmed = apply_tier2_verdict(rule, {"status": "escalated", "confidence": 0.95,
                                           "rationale": "real"})
    assert confirmed["level"] == "likely-malicious" and not confirmed["overrides_rules"]
    assert confirmed["recommended_checks"] == ["isolate"]


def test_analyzer_headline_uses_agent_dismissal(monkeypatch):
    """End to end through analyze(): an agent dismissal flips the headline, and the
    markdown report says the rule score was overruled."""
    import bluecell.analyzer as analyzer
    from conftest import BENIGN_SAMPLES
    from bluecell.report.render import render_markdown

    rules_only = analyzer.analyze([BENIGN_SAMPLES], use_llm=False)
    assert rules_only["incidents"][0]["verdict"]["level"] == "likely-malicious"
    assert "decided_by" not in rules_only["incidents"][0]["verdict"]

    real_run_swarm = analyzer.run_swarm

    def fake_swarm(events, incidents, *a, **kw):
        out = real_run_swarm(events, incidents, *a, **dict(kw, use_llm=False))
        for f in out["findings"]:
            if f["tier"] == 2:
                f.update(status="dismissed", origin="agent", confidence=0.85,
                         rationale="Approved change CHG0042117.")
        return out
    monkeypatch.setattr(analyzer, "run_swarm", fake_swarm)

    result = analyzer.analyze([BENIGN_SAMPLES], use_llm=False)
    v = result["incidents"][0]["verdict"]
    assert v["level"] == "likely-benign" and v["decided_by"] == "tier2-agent"
    md = render_markdown(result)
    assert "LIKELY BENIGN" in md and "overruled the rule-based score" in md


class DismissAll(ScriptedModel):
    """Tier-1 and Tier-2 agents look; Tier-2 dismisses every incident.
    Records which roles were ever called, so we can prove Tier-3 never ran."""

    def __init__(self, incidents):
        super().__init__([])
        self.incidents = incidents
        self.roles_called = set()

    def messages(self, body):
        role = body["system"].split(" on a blue team")[0].replace("You are the ", "")
        self.roles_called.add(role)
        n = len(body["messages"])
        if role == "Tier-2 SOC Analyst" and n == 1:
            return {"content": [
                {"type": "tool_use", "id": f"v{i}", "name": "submit_verdict",
                 "input": {"incident_id": inc.id, "decision": "dismissed",
                           "confidence": 0.8, "rationale": "approved maintenance",
                           "evidence": [inc.events[0].event_id]}}
                for i, inc in enumerate(self.incidents)]}
        if n == 1:
            return {"content": [{"type": "tool_use", "id": "o",
                                 "name": "case_overview", "input": {}}]}
        return {"content": [{"type": "text", "text": "done"}]}


def test_tier3_skipped_when_tier2_agent_dismisses_everything():
    ctx = _ctx()
    model = DismissAll(ctx.incidents)
    ctx.backbone = model
    out = SwarmOrchestrator(ctx).run()
    assert out["tier3_skipped"] and "dismissed all" in out["tier3_skipped"]
    assert out["counts"]["tier3_findings"] == 0
    assert {r["tier"] for r in out["agent_runs"]} == {1, 2}
    assert all(a["tier"] != 3 for a in out["roster"])
    assert model.roles_called == {"Tier-1 SOC Analyst", "Tier-2 SOC Analyst"}
    from bluecell.report.render import _render_swarm
    assert "Tier-3 specialists skipped" in _render_swarm(out)


def test_rule_only_dismissal_still_runs_specialists():
    """Without a model, a rule-based Tier-2 dismissal is advisory: Tier-3 still runs."""
    from bluecell.models import Event
    e = Event(ts="2026-09-26T09:00:00Z", source="syslog", category="other",
              action="log", message="benign", host="h1")
    e.attack.append("T1059")
    ctx = AgentContext(events=[e], incidents=correlate([e], window_minutes=30),
                       iocs=extract_iocs([e]), digest=compress([e]))
    out = SwarmOrchestrator(ctx, use_llm=False).run()
    assert out["counts"]["confirmed_incidents"] == 0
    assert out["tier3_skipped"] is None
    assert 3 in {r["tier"] for r in out["agent_runs"]}
