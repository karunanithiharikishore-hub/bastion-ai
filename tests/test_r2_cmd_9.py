# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-CMD-9: the commander deploys at most one Tier-1 analyst per source.

A second tier1-analyst for a source already triaged is refused with a tool
error, and the refusal reason is kept in the plan log.
"""
from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _last_results, _orch, _text, _use


def _run(script_fns, ctx):
    return _orch(ctx, SwarmModel(ctx, script_fns)).run()


def test_second_tier1_deploy_for_same_source_is_refused():
    ctx = _ctx()
    src = ctx.events[0].source
    errors = []

    def second(body):
        return _use("deploy_agents", {"agents": [
            {"role": "tier1-analyst", "source": src, "reason": "again"}]})

    def record(body):
        errors.append(_last_results(body)[0])
        return _use("deploy_agent", {"role": "tier2-verifier", "reason": "v"})

    script = [
        lambda b: _use("deploy_agents", {"agents": [
            {"role": "tier1-analyst", "source": src, "reason": "a"}]}),
        second,
        record,
        lambda b: _use("finish", {"summary": "s"}),
        lambda b: _text("x"),
    ]
    out = _run(script, ctx)

    err = errors[0]
    assert err["_is_error"] and err["error"] == "deploy rejected"
    assert f"already deployed for source(s) ['{src}']" in " ".join(err["problems"])
    assert out["orchestration"] == "commander"
    assert out["counts"]["tier1_findings"] == 1
    refused = [p for p in out["commander"]["plan"] if p["action"] == "refused"]
    assert len(refused) == 1 and "already deployed" in " ".join(refused[0]["problems"])
    assert out["commander"]["agents_deployed"] == 2  # the tier1 analyst + the verifier


def test_duplicate_source_within_one_batch_is_refused():
    ctx = _ctx()
    src = ctx.events[0].source
    errors = []

    def record(body):
        errors.append(_last_results(body)[0])
        return _use("finish", {"summary": "s"})

    script = [
        lambda b: _use("deploy_agents", {"agents": [
            {"role": "tier1-analyst", "source": src, "reason": "a"},
            {"role": "tier1-analyst", "source": src, "reason": "b"}]}),
        record,
        lambda b: _text("x"),
    ]
    out = _run(script, ctx)

    assert errors[0]["error"] == "deploy rejected"
    assert out["commander"]["agents_deployed"] == 0
    assert [p["action"] for p in out["commander"]["plan"]] == ["refused", "finish"]
