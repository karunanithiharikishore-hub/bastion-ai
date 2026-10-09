# BUG-AGENT-1: the source label the Tier-1 mission gives the model must find that
# source's events in search_events and aggregate (raw names and labels, any case).
import json
import re

from test_injection import _attack_ctx, _box
from bluecell.agents.roles import JuniorSocAnalyst


def test_tier1_mission_label_finds_source_events(tmp_path):
    src = "Palo Alto Networks"
    ctx = _attack_ctx(tmp_path)
    for e in ctx.events:
        e.source = src
    n = len(ctx.events)
    assert n > 0

    agent = JuniorSocAnalyst(src)
    label = re.search(r"source='([^']*)'", agent.brief()).group(1)
    box = _box(ctx, tmp_path, source_scope=agent.source_scope)

    assert json.loads(box.call("search_events", {"source": label, "limit": 200}))["matches"] == n
    assert json.loads(box.call("aggregate", {"group_by": "host", "source": label}))["total"] == n
    # Raw name, in any case, works for both tools too.
    assert json.loads(box.call("search_events", {"source": src.upper(), "limit": 200}))["matches"] == n
    assert json.loads(box.call("aggregate", {"group_by": "host", "source": src.lower()}))["total"] == n
