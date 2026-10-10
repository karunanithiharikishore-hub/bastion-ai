# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""BUG-CMD-10: wrong-typed deploy fields are a validation refusal, and the
refusal is logged with its problems. No real model calls."""
import pytest

from bastion.agents.commander import Dispatcher
from bastion.agents.orchestrator import SwarmOrchestrator
from bastion.agents.runtime import SwarmSession

from test_autonomous_agents import _ctx
from test_commander import SwarmModel


def _dispatcher():
    ctx = _ctx()
    ctx.backbone = SwarmModel(ctx, [])
    return Dispatcher(SwarmOrchestrator(ctx, orchestration="commander"), ctx,
                      SwarmSession(ctx, seed=[]))


@pytest.fixture
def d():
    disp = _dispatcher()
    yield disp
    disp.session.close()   # each dispatcher owns a temp swarm dir


def test_unhashable_role_is_a_logged_validation_refusal(d):
    r = d.handle("deploy", {"agents": [{"role": ["x"], "reason": "r"}]})
    assert r["error"] == "deploy rejected"
    assert any("unknown role" in p for p in r["problems"]), r
    assert len(d.plan) == 1 and d.plan[0]["action"] == "refused"
    assert d.plan[0]["problems"] == r["problems"]


def test_unhashable_tier1_source_is_refused_not_a_crash(d):
    r = d.handle("deploy", {"agents": [
        {"role": "tier1-analyst", "source": ["dns"], "reason": "r"},
        {"role": "tier1-analyst", "source": ["dns"], "reason": "r"}]})
    assert r["error"] == "deploy rejected"
    assert any("needs 'source'" in p for p in r["problems"]), r
    assert len(d.plan) == 1 and d.plan[0]["problems"] == r["problems"]


def test_non_list_agents_is_a_logged_refusal(d):
    r = d.handle("deploy", {"agents": 5})
    assert r["error"] == "deploy rejected" and "must be a list" in r["problems"][0]
    assert len(d.plan) == 1 and d.plan[0]["action"] == "refused"
