"""BUG-FEAT-7: per-agent rows are exclusive (own calls only) and sum to the run total."""
import pytest

from bastion import tracing

USAGE = {"input_tokens": 1000, "output_tokens": 100}


def test_nested_agent_calls_are_counted_once_and_rows_sum_to_total():
    t = tracing.Tracer(persist=False)
    with t.open("soc-lead", "agent", agent="soc-lead"):
        t.record_usage(USAGE, model="claude-sonnet-5")
        with t.open("soc1-edr", "agent", agent="soc1-edr"):
            t.record_usage(USAGE, model="claude-sonnet-5")
            t.record_usage(USAGE, model="claude-sonnet-5")
    s = t.finish()
    rows = {r["agent"]: r for r in s["per_agent"]}
    assert rows["soc-lead"]["llm_calls"] == 1
    assert rows["soc1-edr"]["llm_calls"] == 2
    assert rows["soc-lead"]["cost_usd"] == pytest.approx(0.003)
    assert rows["soc1-edr"]["cost_usd"] == pytest.approx(0.006)
    assert sum(r["llm_calls"] for r in s["per_agent"]) == s["llm_calls"] == 3
    assert sum(r["cost_usd"] for r in s["per_agent"]) == pytest.approx(s["total_cost_usd"])
