"""BUG-FEAT-6 (evals part): unknown eval cost is n/a or ">= x", never a fake 0.0000."""
from bastion import evals

CFG = {"backbone": "off", "repeat": 1}


def _res(total, unknown_calls):
    """analyze() result whose trace reports this total cost."""
    return {"incidents": [], "meta": {"trace": {
        "run_id": "x", "total_cost_usd": total, "cost_unknown_calls": unknown_calls,
        "cost_basis": ["unknown"] if total is None else ["reported"],
        "tokens": {"total": 0}, "llm_calls": 1, "tool_calls": 0}}}


def _case(*obs):
    runs = [dict(evals.observe(_res(t, u)), checks={"tier2": "n/a"}, duration_ms=1,
                 error=None, rep=i) for i, (t, u) in enumerate(obs)]
    return {"name": "c", "expected": {"verdict": "likely-benign"}, "runs": runs,
            "passed": True, "stability": 1.0}


def test_all_unknown_total_is_none_and_prints_na():
    s = evals.aggregate([_case((None, 1))])
    assert s["total_cost_usd"] is None and s["cost_unknown_runs"] == 1
    out = evals.format_report({"config": CFG, "summary": s, "cases": []})
    assert "cost n/a" in out and "$0.0000" not in out


def test_mixed_total_is_partial_sum_with_lower_bound():
    s = evals.aggregate([_case((0.25, 0), (None, 2))])
    assert s["total_cost_usd"] == 0.25 and s["cost_unknown_runs"] == 1
    out = evals.format_report({"config": CFG, "summary": s, "cases": []})
    assert "cost >= $0.2500" in out


def test_all_known_total_unchanged_and_no_runs_is_zero():
    s = evals.aggregate([_case((0.5, 0), (0.5, 0))])
    assert s["total_cost_usd"] == 1.0 and s["cost_unknown_runs"] == 0
    assert evals.aggregate([])["total_cost_usd"] == 0.0
