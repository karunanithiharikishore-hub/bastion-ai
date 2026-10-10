"""ITEM-7 -- analyze() must reject out-of-range limits at the API boundary instead of
silently replacing 0 with the default, keeping negatives, dropping an incident
(max_incidents=-1 slices [:-1]) or crashing on budget_seconds <= 60.
No model calls: use_llm=False, no backbone."""
import pytest

from conftest import BENIGN_SAMPLES
from bluecell import analyzer


@pytest.mark.parametrize("kwargs, match", [
    ({"max_incidents": -1}, "max_incidents"),
    ({"max_incidents": 0}, "max_incidents"),
    ({"max_agents": 0}, "max_agents"),
    ({"max_agents": -3}, "max_agents"),
    ({"max_commander_turns": 0}, "max_commander_turns"),
    ({"max_commander_turns": -1}, "max_commander_turns"),
    ({"votes": 0}, "votes"),
    ({"budget_seconds": 0}, "budget_seconds"),
    ({"budget_seconds": -5}, "budget_seconds"),
    ({"budget_seconds": 30}, "budget_seconds"),
    ({"budget_seconds": 60}, "budget_seconds"),
])
def test_out_of_range_limits_raise_value_error(kwargs, match):
    with pytest.raises(ValueError, match=match):
        analyzer.analyze([BENIGN_SAMPLES], use_llm=False, trace=False, **kwargs)


def test_valid_limits_still_accepted():
    res = analyzer.analyze([BENIGN_SAMPLES], use_llm=False, trace=False,
                           max_incidents=1, max_agents=1, max_commander_turns=1,
                           votes=1, budget_seconds=61)
    assert isinstance(res, dict)
