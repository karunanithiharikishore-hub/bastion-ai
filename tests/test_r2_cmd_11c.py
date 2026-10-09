"""BUG-CMD-11 follow-up 2: meta.agents_deployed counts worker agents only (the
commander is excluded), matching the report and dashboard. No real model calls:
run_swarm is stubbed with a canned swarm result."""
import bluecell.analyzer as analyzer
from conftest import BENIGN_SAMPLES
from test_repeatability import FakeBackbone


def _run(monkeypatch, swarm):
    monkeypatch.setattr(analyzer, "run_swarm", lambda *a, **k: swarm)
    return analyzer.analyze([BENIGN_SAMPLES], backbone=FakeBackbone(), intel_store=None,
                            orchestration="fixed", trace=False, cache="off")


def test_meta_agents_deployed_excludes_commander(monkeypatch):
    swarm = {"findings": [], "agent_count": 3, "worker_count": 2, "counts": {},
             "orchestration": "commander",
             "orchestrator": {"name": "soc-lead", "role": "x", "tier": 0}}
    out = _run(monkeypatch, swarm)
    assert out["meta"]["agents_deployed"] == 2


def test_meta_agents_deployed_falls_back_to_agent_count(monkeypatch):
    swarm = {"findings": [], "agent_count": 4, "counts": {}, "orchestration": "fixed"}
    out = _run(monkeypatch, swarm)
    assert out["meta"]["agents_deployed"] == 4
