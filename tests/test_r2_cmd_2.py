# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""BUG-CMD-2: a voting Tier-2 deploy shares the budget left at its start.

The K vote runs go one after another, so their timeouts must add up to no
more than the time left: fewer votes when each run could not get
MIN_WORKER_SECONDS.
"""
import bastion.agents.runtime as R
from bastion.agents import AgentContext, SwarmOrchestrator
from bastion.agents.commander import Dispatcher
from bastion.agents.runtime import SwarmSession

from test_integration import _pipeline
from conftest import SAMPLES


class _Backbone:
    resolved = "cli"
    model = "fake"


def _deploy_verifier(votes, budget, monkeypatch):
    runs = []

    def fake_cli(agent, session, backbone, max_turns, timeout, model=None):
        runs.append(timeout)
        return {"findings": [], "verdicts": [], "calls": [{"tool": "x", "ok": True}],
                "summary": "", "turns": 1, "cost_usd": None, "error": None,
                "truncated": False}

    monkeypatch.setattr(R, "_run_cli", fake_cli)
    events, incidents = _pipeline(SAMPLES)
    ctx = AgentContext(events=events, incidents=incidents, iocs={}, digest="",
                       backbone=_Backbone())
    orch = SwarmOrchestrator(ctx, orchestration="commander", votes=votes)
    session = SwarmSession(ctx, seed=[])
    d = Dispatcher(orch, ctx, session, budget_seconds=budget)
    try:
        d.handle("deploy", {"agents": [{"role": "tier2-verifier", "reason": "verify"}]})
    finally:
        session.close()
    return runs


def test_vote_runs_share_remaining_budget(monkeypatch):
    runs = _deploy_verifier(votes=3, budget=400, monkeypatch=monkeypatch)
    assert len(runs) == 3
    assert sum(runs) <= 400


def test_votes_shrink_when_runs_would_be_too_short(monkeypatch):
    runs = _deploy_verifier(votes=3, budget=100, monkeypatch=monkeypatch)
    assert len(runs) == 1
    assert sum(runs) <= 100
