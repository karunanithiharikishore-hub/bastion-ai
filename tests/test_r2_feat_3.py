# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""BUG-FEAT-3 -- the run cache must not store a result whose model output was
unusable: an analyst/reviewer answer that was not JSON, or a Tier-2 agent run
that filed no verdict for an incident. Offline: fake backbones only."""
import json

import pytest

from conftest import SAMPLES
from bastion import analyzer, cache as run_cache

BB = object()   # any non-None backbone: the LLM was on


def _result(**over):
    base = {"meta": {}, "incidents": [], "swarm": {"agent_runs": []},
            "ai_analysis": {"available": True, "final_verdict": "likely-malicious",
                            "lead": {"verdict": "likely-malicious"},
                            "review": {"corrected_verdict": "likely-malicious"}}}
    base.update(over)
    return base


def test_analyst_lead_not_json_is_not_cached():
    r = _result()
    r["ai_analysis"]["lead"] = {"raw": "Sorry, I can't help with that."}
    r["ai_analysis"]["final_verdict"] = None
    assert run_cache.uncacheable_reason(r, BB) == "AI analyst gave no usable verdict"


def test_analyst_review_not_json_is_not_cached():
    r = _result()
    r["ai_analysis"]["review"] = {"raw": "not json"}
    assert "review was not valid JSON" in run_cache.uncacheable_reason(r, BB)


def test_analyst_without_any_verdict_is_not_cached():
    r = _result()
    r["ai_analysis"]["final_verdict"] = None
    assert run_cache.uncacheable_reason(r, BB) == "AI analyst gave no usable verdict"


def test_valid_analyst_answer_is_still_cacheable():
    assert run_cache.uncacheable_reason(_result(), BB) is None


def test_tier2_run_with_incident_missing_verdict_is_not_cached():
    r = _result()
    r["swarm"]["agent_runs"] = [{
        "agent": "soc2-lead", "tier": 2, "mode": "autonomous", "error": None,
        "note": "['INC-1'] got no verdict and no Tier-1 candidates"}]
    assert "filed no verdict" in run_cache.uncacheable_reason(r, BB)


def test_tier2_rules_decided_headline_is_not_cached():
    r = _result()
    r["swarm"]["agent_runs"] = [{
        "agent": "soc2-lead", "tier": 2, "mode": "autonomous", "error": None,
        "note": "no agent verdict for ['INC-1']; rules decided those"}]
    assert "filed no verdict" in run_cache.uncacheable_reason(r, BB)


def test_tier2_run_with_all_verdicts_is_cacheable():
    r = _result()
    r["swarm"]["agent_runs"] = [{"agent": "soc2-lead", "tier": 2,
                                 "mode": "autonomous", "error": None}]
    assert run_cache.uncacheable_reason(r, BB) is None


def test_run_without_llm_is_still_uncacheable_for_its_own_reason():
    assert run_cache.uncacheable_reason(_result(), None) == "no LLM (deterministic run)"


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "cache"
    monkeypatch.setenv(run_cache.CACHE_ENV, str(d))
    return d


class _NoVerdictBackbone:
    """Tier-2 agent looks once, then stops without calling submit_verdict."""
    resolved = "api"
    temperature = 0.0
    sampling = "temperature=0"
    model = "fake-main"

    def complete(self, prompt, system=None, max_tokens=1500):
        return json.dumps({"verdict": "needs-review", "corrected_verdict": "needs-review"})

    def messages(self, body):
        if len(body["messages"]) == 1:
            return {"content": [{"type": "tool_use", "id": "o",
                                 "name": "case_overview", "input": {}}]}
        return {"content": [{"type": "text", "text": "done"}]}


def test_end_to_end_tier2_without_verdict_is_not_stored(cache_dir):
    out = analyzer.analyze([SAMPLES], backbone=_NoVerdictBackbone(), intel_store=None,
                           orchestration="fixed", cache="use", trace=False)
    assert out["incidents"], "sample logs should produce incidents"
    assert "filed no verdict" in out["meta"]["cache"]
    assert not cache_dir.exists() or not list(cache_dir.glob("*.json"))
