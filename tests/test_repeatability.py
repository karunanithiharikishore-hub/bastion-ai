# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Repeatability & cost: run cache, Tier-2 self-consistency voting, Tier-1
skipping, per-tier models, deterministic decoding. All offline: fake
backbones and a fake ``claude`` script stand in for the model."""
import dataclasses
import json
import os
import stat
from datetime import timedelta

import pytest

from conftest import SAMPLES, BENIGN_SAMPLES
from bluecell import analyzer, cache as run_cache
from bluecell.cli import build_parser
from bluecell.ingest import ingest_path
from bluecell.llm.backbone import LLMBackbone
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.agents import AgentContext, SwarmOrchestrator, toolbox
from bluecell.agents import roles
from bluecell.agents.budget import (
    active_tier1_sources, plan_swarm, plan_before_after, TIER_MAX_TURNS,
)
from bluecell.agents.roles import JuniorSocAnalyst, SeniorSocAnalyst
from bluecell.agents.runtime import SwarmSession
from bluecell.agents.voting import tally


def _events(path=SAMPLES):
    events = normalize(ingest_path(path))
    map_attack(events)
    return events


def _ctx(backbone=None, events=None):
    events = events if events is not None else _events()
    return AgentContext(events=events, incidents=correlate(events, window_minutes=60),
                        iocs=extract_iocs(events), digest=compress(events),
                        backbone=backbone)


def _role(body):
    return body["system"].split(" on a blue team")[0].replace("You are the ", "")


class FakeBackbone:
    """API-style backbone: every agent looks once then stops; analyst and
    narrative calls return a fixed JSON answer. Counts every model call."""
    resolved = "api"
    temperature = 0.0
    sampling = "temperature=0"

    def __init__(self, model="fake-main"):
        self.model = model
        self.calls = 0
        self.bodies = []

    def complete(self, prompt, system=None, max_tokens=1500):
        self.calls += 1
        return json.dumps({"verdict": "needs-review", "confidence": 0.5,
                           "headline": "fake", "agree": True,
                           "corrected_verdict": "needs-review", "notes": "ok"})

    def messages(self, body):
        self.calls += 1
        self.bodies.append(body)
        if len(body["messages"]) == 1:
            return {"content": [{"type": "tool_use", "id": "o",
                                 "name": "case_overview", "input": {}}]}
        return {"content": [{"type": "text", "text": "done"}]}


class VerdictBackbone(FakeBackbone):
    """FakeBackbone whose Tier-2 agent files a dismissal on every incident of
    ``path``, citing a real event. A Tier-2 run with no verdict is not cached."""

    def __init__(self, path, model="fake-main"):
        super().__init__(model)
        from bluecell.agents import injection
        events = _events(path)
        injection.tag_events(events)
        self.incidents = correlate(events, window_minutes=60)

    def messages(self, body):
        if _role(body) == "Tier-2 SOC Analyst" and len(body["messages"]) == 1:
            self.calls += 1
            self.bodies.append(body)
            return {"content": [
                {"type": "tool_use", "id": f"v{i}", "name": "submit_verdict",
                 "input": {"incident_id": inc.id, "decision": "dismissed",
                           "confidence": 0.9, "rationale": "approved maintenance",
                           "evidence": [inc.events[0].event_id]}}
                for i, inc in enumerate(self.incidents)]}
        return super().messages(body)


# ---------------------------------------------------------------------------
# Cache key
# ---------------------------------------------------------------------------
def _key(events, backbone=None, settings=None):
    material = run_cache.key_material(events, backbone=backbone or FakeBackbone(),
                                      intel_store=None, settings=settings or {"votes": 1})
    return run_cache.cache_key(material)


def test_cache_key_is_stable():
    assert _key(_events()) == _key(_events())


def test_cache_key_changes_with_logs_model_mission_and_settings(monkeypatch):
    events = _events()
    base = _key(events)
    assert _key(events[:-1]) != base                                  # fewer events
    edited = list(events)
    edited[0] = dataclasses.replace(events[0], message=events[0].message + " x")
    assert _key(edited) != base                                       # content change
    assert _key(_events(BENIGN_SAMPLES)) != base                      # other logs
    assert _key(events, FakeBackbone(model="other-model")) != base    # model
    assert _key(events, settings={"votes": 3}) != base                # orchestration
    prompts = run_cache.prompt_fingerprint()
    monkeypatch.setattr(roles.ThreatHunter, "mission", "Mission: something else.")
    assert run_cache.prompt_fingerprint() != prompts                  # mission text
    assert _key(events) != base


def test_cache_key_covers_tool_schemas(monkeypatch):
    before = run_cache.tool_schema_fingerprint()
    specs = [dict(t) for t in toolbox.TOOL_SPECS]
    specs[0]["description"] = "changed"
    monkeypatch.setattr(toolbox, "TOOL_SPECS", specs)
    assert run_cache.tool_schema_fingerprint() != before


# ---------------------------------------------------------------------------
# Cache behaviour through analyze()
# ---------------------------------------------------------------------------
@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "cache"
    monkeypatch.setenv(run_cache.CACHE_ENV, str(d))
    return d


def _analyze(backbone, **kw):
    # These fakes model the fixed tiered flow; with orchestration "auto" a
    # model backbone would first get the Incident Commander (see test_integration).
    kw.setdefault("orchestration", "fixed")
    return analyzer.analyze([BENIGN_SAMPLES], backbone=backbone, intel_store=None, **kw)


def test_cache_miss_then_hit_returns_identical_result_without_model_calls(cache_dir):
    bb = VerdictBackbone(BENIGN_SAMPLES)
    first = _analyze(bb, cache="use")
    assert first["meta"]["cache"] == "miss (stored)"
    assert len(list(cache_dir.glob("*.json"))) == 1
    calls = bb.calls
    second = _analyze(bb, cache="use")
    assert bb.calls == calls                                  # nothing re-ran
    assert second["meta"]["cache"] == "hit"
    assert second["meta"]["cache_key"] == first["meta"]["cache_key"]
    assert second["meta"]["original_timing_ms"] == first["meta"]["timing_ms"]
    assert second["meta"]["original_generated"] == first["meta"]["generated"]
    assert second["incidents"] == json.loads(json.dumps(first["incidents"], default=str))
    assert second["swarm"]["findings"] == first["swarm"]["findings"]


def test_cache_refresh_reruns_and_overwrites(cache_dir):
    bb = VerdictBackbone(BENIGN_SAMPLES)
    first = _analyze(bb, cache="use")
    calls = bb.calls
    again = _analyze(bb, cache="refresh")
    assert bb.calls > calls and again["meta"]["cache"] == "refreshed"
    entry = run_cache.load(first["meta"]["cache_key"])
    assert entry["result"]["meta"]["generated"] == again["meta"]["generated"]


def test_no_cache_neither_reads_nor_writes(cache_dir):
    bb = FakeBackbone()
    out = _analyze(bb, cache="off")
    assert out["meta"]["cache"] == "off" and not cache_dir.exists()
    _analyze(bb, cache="use")
    calls = bb.calls
    assert _analyze(bb, cache="off")["meta"]["cache"] == "off"
    assert bb.calls > calls                                   # ignored the stored run


def test_deterministic_runs_are_not_cached(cache_dir):
    out = analyzer.analyze([BENIGN_SAMPLES], backbone=None, use_llm=False, cache="use")
    assert out["meta"]["cache"].startswith("n/a") and not cache_dir.exists()


def test_agent_error_is_never_cached(cache_dir):
    class OneBroken(FakeBackbone):
        def messages(self, body):
            if _role(body) == "Threat Hunter":
                raise RuntimeError("backbone down")
            return super().messages(body)
    out = _analyze(OneBroken(), cache="use")
    assert out["meta"]["cache"].startswith("miss (not stored")
    assert "fell back" in out["meta"]["cache"] or "errored" in out["meta"]["cache"]
    assert not cache_dir.exists() or not list(cache_dir.glob("*.json"))


def test_budget_truncated_run_is_never_cached(cache_dir):
    class NeverStops(FakeBackbone):
        def messages(self, body):
            self.calls += 1
            return {"content": [{"type": "tool_use", "id": f"o{len(body['messages'])}",
                                 "name": "case_overview", "input": {}}]}
    out = _analyze(NeverStops(), cache="use")
    assert "turn budget" in out["meta"]["cache"]
    runs = out["swarm"]["agent_runs"]
    assert all(r["truncated"] for r in runs if r.get("mode") == "autonomous")
    assert {r["turns"] for r in runs if r["tier"] == 1} == {TIER_MAX_TURNS[1]}


def test_failed_analyst_call_is_never_cached(cache_dir):
    class NoComplete(FakeBackbone):
        def complete(self, prompt, system=None, max_tokens=1500):
            raise RuntimeError("down")
    out = _analyze(NoComplete(), cache="use")
    assert out["meta"]["cache"].startswith("miss (not stored")


# ---------------------------------------------------------------------------
# Voting
# ---------------------------------------------------------------------------
def _v(decision, conf=0.8, sev="high", ev=("e1",)):
    return {"incident_id": "I", "decision": decision, "confidence": conf,
            "severity": sev, "rationale": f"{decision} because", "evidence": list(ev),
            "reviewed_candidates": []}


def test_tally_majority_scales_confidence_by_agreement():
    res = tally([{"I": _v("confirmed", 0.9, ev=("a",))},
                 {"I": _v("dismissed", 0.6)},
                 {"I": _v("confirmed", 0.7, sev="critical", ev=("b",))}], ["I"])["I"]
    assert res["outcome"] == "majority" and res["decision"] == "confirmed"
    assert res["votes"]["confirmed"] == 2 and res["votes"]["dismissed"] == 1
    assert res["votes"]["agreement"] == 0.67
    assert res["verdict"]["confidence"] == round(0.8 * 0.67, 2)
    assert res["verdict"]["evidence"] == ["a", "b"]
    assert res["verdict"]["severity"] == "critical"           # tie -> more severe
    assert res["verdict"]["rationale"] == "confirmed because"


def test_tally_unanimous_keeps_confidence():
    res = tally([{"I": _v("dismissed", 0.8)}] * 3, ["I"])["I"]
    assert res["votes"]["agreement"] == 1.0 and res["verdict"]["confidence"] == 0.8


def test_tally_tie_abstention_and_failures_are_splits():
    tie = tally([{"I": _v("confirmed")}, {"I": _v("dismissed")}], ["I"])["I"]
    assert tie["outcome"] == "split" and tie["verdict"] is None
    # 1 confirmed, 2 abstained: not a majority of the completed runs.
    thin = tally([{"I": _v("confirmed")}, {}, {}], ["I"])["I"]
    assert thin["outcome"] == "split" and thin["votes"]["abstained"] == 2
    # A failed run does not count: 2 of 2 completed runs agree.
    failed = tally([{"I": _v("confirmed")}, None, {"I": _v("confirmed")}], ["I"])["I"]
    assert failed["outcome"] == "majority" and failed["votes"]["failed"] == 1
    assert tally([None, None], ["I"])["I"]["outcome"] == "split"


class VotingModel(FakeBackbone):
    """Tier-2 run i files decisions[i] on every incident."""

    def __init__(self, incidents, decisions, tier1_ids=()):
        super().__init__()
        self.incidents, self.decisions = incidents, list(decisions)
        self.tier2_runs = 0
        self.board_at_start = []

    def messages(self, body):
        n = len(body["messages"])
        if _role(body) == "Tier-2 SOC Analyst" and n == 1:
            self.tier2_runs += 1
            decision = self.decisions[self.tier2_runs - 1]
            return {"content": [{"type": "tool_use", "id": "b", "name": "read_board",
                                 "input": {}}] + [
                {"type": "tool_use", "id": f"v{i}", "name": "submit_verdict",
                 "input": {"incident_id": inc.id, "decision": decision,
                           "confidence": 0.9, "rationale": f"vote {self.tier2_runs}",
                           "evidence": [inc.events[0].event_id]}}
                for i, inc in enumerate(self.incidents)]}
        if _role(body) == "Tier-2 SOC Analyst" and n == 3:
            board = json.loads(body["messages"][2]["content"][0]["content"])
            self.board_at_start.append(board["entries"])
        return super().messages(body) if n == 1 else {
            "content": [{"type": "text", "text": "done"}]}


def _verify(decisions, votes):
    ctx = _ctx()
    inc = ctx.incidents[0]
    tier1 = JuniorSocAnalyst(inc.events[0].source).analyze(ctx)
    model = VotingModel(ctx.incidents, decisions)
    ctx.backbone = model
    session = SwarmSession(ctx, seed=SwarmOrchestrator._seed(tier1))
    try:
        senior = SeniorSocAnalyst(name="soc2-lead", votes=votes)
        found = senior.verify(ctx, tier1, use_llm=True, session=session)
        board = session.board.read()
    finally:
        session.close()
    return model, senior, next(f for f in found if f.incident_id == inc.id), board


def test_tier2_majority_vote_decides_and_is_recorded():
    model, senior, f, board = _verify(["confirmed", "dismissed", "confirmed"], 3)
    assert model.tier2_runs == 3
    assert f.origin == "agent" and f.status == "escalated"
    assert f.votes["confirmed"] == 2 and f.votes["dismissed"] == 1
    assert f.votes["agreement"] == 0.67 and f.confidence == round(0.9 * 0.67, 2)
    run = senior.last_run
    assert run["mode"] == "autonomous" and run["votes"]["k"] == 3
    assert run["votes"]["per_incident"][f.incident_id]["outcome"] == "majority"
    assert len(run["vote_runs"]) == 3
    # Votes are independent: no run saw another run's verdict on the board ...
    assert all(not any(e.get("kind") == "verdict" for e in entries)
               for entries in model.board_at_start)
    # ... and only the merged verdict is left on the board for Tier-3.
    verdicts = [e for e in board if e.get("kind") == "verdict"]
    assert len(verdicts) == len(model.incidents) and "votes" in verdicts[0]


def test_tier2_split_vote_keeps_rule_verdict_at_low_confidence():
    _, senior, f, _ = _verify(["confirmed", "dismissed"], 2)
    assert f.origin == "rules" and f.votes["needs_review"] is True
    assert f.confidence <= SeniorSocAnalyst.SPLIT_VOTE_MAX_CONFIDENCE
    assert "split Tier-2 vote" in f.title
    assert senior.last_run["votes"]["per_incident"][f.incident_id]["outcome"] == "split"


def test_single_vote_is_unchanged_behaviour():
    model, senior, f, _ = _verify(["dismissed"], 1)
    assert model.tier2_runs == 1 and f.status == "dismissed" and f.votes == {}
    assert "votes" not in senior.last_run


def test_votes_flow_into_the_headline(cache_dir):
    events = _events(BENIGN_SAMPLES)
    incidents = correlate(events, window_minutes=60)
    model = VotingModel(incidents, ["dismissed", "dismissed", "confirmed"])
    out = _analyze(model, votes=3)
    v = out["incidents"][0]["verdict"]
    assert v["decided_by"] == "tier2-agent" and v["level"] == "likely-benign"
    assert v["votes"]["dismissed"] == 2 and v["votes"]["confirmed"] == 1
    assert out["meta"]["repeatability"]["votes"] == 3


# ---------------------------------------------------------------------------
# Tier-1 skipping and budgets
# ---------------------------------------------------------------------------
def _events_with_idle_source():
    events = _events()
    quiet = next(e for e in events if not e.attack)
    extra = dataclasses.replace(quiet, source="vpn", ts=quiet.ts + timedelta(days=30),
                                message="vpn keepalive")
    return events + [extra]


def test_active_tier1_sources_skips_sources_without_incident_events():
    events = _events_with_idle_source()
    incidents = correlate(events, window_minutes=60)
    run, skipped = active_tier1_sources(events, incidents)
    assert skipped == ["vpn"] and "vpn" not in run
    assert active_tier1_sources(events, incidents, skip_idle=False)[1] == []
    assert active_tier1_sources(events, [])[1] == []          # no incidents: keep all


def test_orchestrator_skips_idle_tier1_agent():
    model = FakeBackbone()
    ctx = _ctx(model, events=_events_with_idle_source())
    out = SwarmOrchestrator(ctx).run()
    run = next(r for r in out["agent_runs"] if r["agent"] == "soc1-vpn")
    assert run["mode"] == "skipped (no incident events)"
    prompts = [b["system"] for b in model.bodies]
    assert not any("'vpn' log source" in p for p in prompts)
    assert any("'edr' log source" in p for p in prompts)
    # --all-tier1 runs it.
    model2 = FakeBackbone()
    out2 = SwarmOrchestrator(_ctx(model2, events=_events_with_idle_source()),
                             skip_idle_tier1=False).run()
    assert next(r for r in out2["agent_runs"]
                if r["agent"] == "soc1-vpn")["mode"] == "autonomous"


def test_rules_mode_never_marks_tier1_skipped():
    out = SwarmOrchestrator(_ctx(events=_events_with_idle_source()), use_llm=False).run()
    assert {r["mode"] for r in out["agent_runs"]} == {"rules"}


def test_plan_counts_processes_and_turns():
    events = _events()
    incidents = correlate(events, window_minutes=60)
    plan = plan_before_after(events, incidents)
    assert plan["before"]["processes"] == 16 and plan["before"]["max_turns"] == 272
    assert plan["after"]["max_turns"] < plan["before"]["max_turns"]
    idle = _events_with_idle_source()
    p = plan_swarm(idle, correlate(idle, window_minutes=60), votes=3)
    assert p["tier1_skipped"] == ["vpn"] and p["tier2_runs"] == 3


def test_tier_turn_caps_and_tool_output_cap(monkeypatch, tmp_path):
    assert JuniorSocAnalyst("edr").max_turns == TIER_MAX_TURNS[1]
    assert SeniorSocAnalyst().max_turns == TIER_MAX_TURNS[2]
    assert roles.ThreatHunter().max_turns == TIER_MAX_TURNS[3]
    assert TIER_MAX_TURNS[1] < TIER_MAX_TURNS[3]
    ctx = _ctx()
    monkeypatch.setattr(toolbox, "MAX_TOOL_RESULT_CHARS", 300)
    box = toolbox.SecurityToolbox(ctx, "t", "r", toolbox.Blackboard(str(tmp_path / "b")))
    text = box.call("search_events", {"limit": 200})
    assert len(text) < 400 and "truncated" in text


# ---------------------------------------------------------------------------
# Models, decoding and backbone selection
# ---------------------------------------------------------------------------
def test_api_driver_uses_tier1_model_and_temperature_zero():
    model = FakeBackbone(model="main-model")
    SwarmOrchestrator(_ctx(model), tier1_model="claude-haiku-4-5").run()
    by_tier = {}
    for b in model.bodies:
        by_tier.setdefault(_role(b), set()).add(b["model"])
        assert b["temperature"] == 0.0
    assert by_tier["Tier-1 SOC Analyst"] == {"claude-haiku-4-5"}
    assert by_tier["Tier-2 SOC Analyst"] == {"main-model"}
    assert by_tier["Threat Hunter"] == {"main-model"}


def _fake_claude(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "argv.jsonl"
    script = bindir / "claude"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"open({str(log)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "sys.stdin.read()\n"
        "print(json.dumps({'type': 'result', 'subtype': 'success', 'result': 'ok',"
        " 'num_turns': 1}))\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return log


def _flag(argv, name):
    return argv[argv.index(name) + 1]


def test_cli_driver_passes_per_tier_model_and_turn_caps(tmp_path, monkeypatch):
    log = _fake_claude(tmp_path, monkeypatch)
    bb = LLMBackbone(mode="cli", model="main-model")
    assert bb.resolved == "cli"
    SwarmOrchestrator(_ctx(bb), tier1_model="claude-haiku-4-5").run()
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(calls) == 13                                   # 5 + 1 + 7 agents
    for argv in calls:
        role = _flag(argv, "--system-prompt").split(" on a blue team")[0]
        tier = 1 if "Tier-1" in role else 2 if "Tier-2" in role else 3
        assert _flag(argv, "--model") == ("claude-haiku-4-5" if tier == 1 else "main-model")
        assert int(_flag(argv, "--max-turns")) == TIER_MAX_TURNS[tier]


def test_auto_backbone_prefers_api_when_key_set(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch)
    assert LLMBackbone(mode="auto").resolved == "cli"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    bb = LLMBackbone(mode="auto")
    assert bb.resolved == "api" and bb.temperature == 0.0
    assert bb.sampling == "temperature=0"
    assert LLMBackbone(mode="cli").sampling.startswith("cli default")


def test_api_complete_sends_temperature_zero(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    bb = LLMBackbone(mode="api")
    sent = []
    monkeypatch.setattr(bb, "messages", lambda body: sent.append(body) or {
        "content": [{"type": "text", "text": "hi"}]})
    assert bb.complete("p", system="s") == "hi"
    assert sent[0]["temperature"] == 0.0


def test_cli_flags_parse():
    p = build_parser()
    a = p.parse_args(["analyze", "x", "--votes", "3", "--model-tier1",
                      "claude-haiku-4-5", "--refresh", "--all-tier1"])
    assert (a.votes, a.model_tier1, a.refresh, a.no_cache, a.all_tier1) == \
        (3, "claude-haiku-4-5", True, False, True)
    with pytest.raises(SystemExit):
        p.parse_args(["analyze", "x", "--no-cache", "--refresh"])
    with pytest.raises(SystemExit):
        p.parse_args(["analyze", "x", "--votes", "0"])
