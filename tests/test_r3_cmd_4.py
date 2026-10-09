# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""R3 CMD-4: distinct raw sources must get distinct shown labels, so a label
the commander reads back deploys the source it was shown for. No real model calls."""
from bluecell.agents.commander import Dispatcher
from bluecell.agents.orchestrator import SwarmOrchestrator
from bluecell.agents.runtime import SwarmSession

from test_autonomous_agents import _ctx
from test_commander import SwarmModel

ZW = "​"


def _dispatcher_for(names):
    ctx = _ctx()
    ctx.backbone = SwarmModel(ctx, [])
    for i, e in enumerate(ctx.events):
        e.source = names[i % len(names)]
    return Dispatcher(SwarmOrchestrator(ctx, orchestration="commander"), ctx,
                      SwarmSession(ctx, seed=[]))


def test_each_raw_source_gets_its_own_label_and_deploys_itself():
    names = ["edr", "edr" + ZW, "L" * 200 + "-prod", "L" * 200 + "-prox"]
    d = _dispatcher_for(names)
    try:
        shown = d.handle("list_roles", {})["sources"]
        assert len(shown) == len(set(d.sources)) == len(names)
        captured = []
        d._deploy = lambda items: captured.append(items) or {"ok": 1}
        for label in shown:
            d.handle("deploy", {"agents": [{"role": "tier1-analyst", "source": label,
                                            "reason": "r"}]})
        assert {c[0]["source"] for c in captured} == set(names)
    finally:
        d.session.close()
