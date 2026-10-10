from types import SimpleNamespace

from bluecell.agents.budget import TIER_MAX_TURNS, plan_swarm


def _ev(source):
    return SimpleNamespace(source=source)


def test_partial_tier_turns_override_keeps_default_caps_for_missing_tiers():
    events = [_ev("auth")]
    incidents = [SimpleNamespace(events=events)]
    plan = plan_swarm(events, incidents, tier_turns={1: 5})
    assert plan["turn_caps"] == {1: 5, 2: TIER_MAX_TURNS[2], 3: TIER_MAX_TURNS[3]}
    # 1 tier-1 run at 5 turns, 1 tier-2 run and 7 tier-3 runs at their defaults.
    assert plan["max_turns"] == 5 + TIER_MAX_TURNS[2] + 7 * TIER_MAX_TURNS[3]


def test_partial_tier_turns_override_commander_plan_does_not_raise():
    events = [_ev("auth")]
    incidents = [SimpleNamespace(events=events)]
    plan = plan_swarm(events, incidents, tier_turns={3: 4},
                      orchestration="commander")
    assert plan["turn_caps"][1] == TIER_MAX_TURNS[1]
    assert plan["turn_caps"][2] == TIER_MAX_TURNS[2]
    assert plan["turn_caps"][3] == 4
