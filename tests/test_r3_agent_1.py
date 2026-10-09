# BUG-R3-AGENT-1: case_overview must keep every Tier-1 candidate id in earlier_tiers
# (bulky fields go before items), and any truncation notice must name real tools.
import json

from test_injection import _attack_ctx, _box
from bluecell.agents import toolbox


def _seed(ctx, n=12):
    inc = ctx.incidents[0].id
    return [{"id": f"F-{i:04d}", "agent": f"soc1-src-{i:08x}", "tier": 1,
             "title": "Suspicious activity " + "x" * 150, "status": "proposed",
             "severity": "high", "confidence": 0.8, "incident_id": inc, "attack": ["T1059"],
             "evidence": [e.event_id for e in ctx.events[:15]], "rationale": "r" * 600}
            for i in range(n)]


def test_all_tier1_candidates_are_visible_to_tier2(tmp_path):
    ctx = _attack_ctx(tmp_path)
    seed = _seed(ctx, 12)
    box = _box(ctx, tmp_path, board_seed=seed)
    text = box.call("case_overview", {})
    res = json.loads(text)
    assert len(text) <= toolbox.MAX_TOOL_RESULT_CHARS
    assert {s["id"] for s in res["earlier_tiers"]} == {s["id"] for s in seed}


def test_truncation_notice_names_only_tools_that_exist(tmp_path, monkeypatch):
    ctx = _attack_ctx(tmp_path)
    box = _box(ctx, tmp_path, board_seed=_seed(ctx, 40))
    monkeypatch.setattr(toolbox, "MAX_TOOL_RESULT_CHARS", 3000)
    res = json.loads(box.call("case_overview", {}))
    assert "omitted from earlier_tiers" in res["truncated"]
    assert "use filters or a smaller limit" not in res["truncated"]
    assert "get_incident" in toolbox.TOOL_NAMES and "get_incident" in res["truncated"]
