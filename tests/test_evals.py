# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Eval suite: case format, scoring, aggregation, runner, CLI. Offline only."""
import ipaddress
import json
import os
import re
import shutil

import pytest

from bastion import evals
from bastion.cli import main

CASES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "evals", "cases")
_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _obs(**kw):
    base = {"verdict": "likely-malicious", "tier2": None, "tier2_rule": None,
            "incidents": 1, "text": "evil 203.0.113.9", "cost_usd": 0.0, "tokens": 0}
    base.update(kw)
    return base


def test_shipped_cases_are_valid_and_realistic():
    cases = evals.load_cases(CASES)
    assert len(cases) >= 8
    for c in cases:
        assert c["problems"] == [], c["name"]
        assert c["files"], c["name"]
    verdicts = {c["expected"]["verdict"] for c in cases}
    assert {"likely-malicious", "likely-benign"} <= verdicts


def test_shipped_cases_use_only_documentation_or_private_ips():
    pat = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    for c in evals.load_cases(CASES):
        for f in c["files"]:
            for m in pat.findall(open(f, encoding="utf-8", errors="replace").read()):
                try:
                    ip = ipaddress.ip_address(m)
                except ValueError:
                    continue   # version strings etc.
                ok = (ip.is_private or ip.is_loopback or ip.is_unspecified
                      or any(ip in n for n in _DOC_NETS))
                assert ok, f"{f}: public IP {m}"


def test_validate_expected_rejects_bad_payloads():
    assert evals.validate_expected({"verdict": "likely-benign", "tier2": None}) == []
    assert evals.validate_expected([]) 
    assert evals.validate_expected({"verdict": "bad"})
    assert evals.validate_expected({"verdict": "likely-benign", "tier2": "maybe"})
    assert evals.validate_expected({"verdict": "likely-benign", "must_mention": "x"})
    assert evals.validate_expected({"verdict": "likely-benign", "min_incidents": -1})
    assert evals.validate_expected({"verdict": "likely-benign", "min_incidents": True})


def test_score_checks_each_dimension():
    exp = {"verdict": "likely-malicious", "tier2": "confirmed",
           "must_mention": ["203.0.113.9"], "must_not_mention": ["innocent"],
           "min_incidents": 1}
    ok = evals.score(exp, _obs(tier2="confirmed"))
    assert ok["passed"] and ok["checks"]["tier2"] == "pass"
    bad = evals.score(exp, _obs(verdict="likely-benign", tier2="dismissed",
                                text="Innocent", incidents=0))
    assert not bad["passed"]
    assert {k for k, v in bad["checks"].items() if v == "fail"} == {
        "verdict", "tier2", "must_mention", "must_not_mention", "min_incidents"}
    # case-insensitive mention
    assert evals.score({"verdict": "likely-malicious", "must_mention": ["EVIL"]},
                       _obs())["passed"]
    # a rules-only Tier-2 (tier2=None) is never scored
    assert evals.score(exp, _obs(tier2=None))["checks"]["tier2"] == "n/a"


def test_observe_no_incidents_counts_as_benign():
    assert evals.observe({"incidents": []})["verdict"] == "likely-benign"


def test_observe_reads_agent_tier2_only():
    res = {"incidents": [{"id": "INC-1", "verdict": {"level": "needs-review"}}],
           "swarm": {"findings": [
               {"tier": 2, "incident_id": "INC-1", "origin": "rules", "status": "escalated"},
               {"tier": 2, "incident_id": "INC-1", "origin": "agent", "status": "dismissed"},
               {"tier": 2, "incident_id": "INC-9", "origin": "agent", "status": "escalated"}]}}
    o = evals.observe(res)
    assert o["tier2"] == "dismissed" and o["tier2_rule"] == "confirmed"


def _fake_analyze(verdicts):
    """analyze_fn returning successive verdicts."""
    seq = list(verdicts)

    def fn(files, **kw):
        v = seq.pop(0)
        return {"incidents": [{"id": "I1", "verdict": {"level": v}}],
                "meta": {"trace": {"run_id": "x", "total_cost_usd": 0.5, "cost_basis": ["reported"],
                                   "tokens": {"total": 100}, "llm_calls": 2, "tool_calls": 3}}}
    return fn


def _two_case_dir(tmp_path):
    for name, v in (("mal", "likely-malicious"), ("ben", "likely-benign")):
        d = tmp_path / name
        d.mkdir()
        (d / "a.log").write_text("x\n")
        (d / "expected.json").write_text(json.dumps({"description": name, "verdict": v, "tier2": None}))
    return str(tmp_path)


def test_aggregate_metrics_and_cost(tmp_path):
    # mal -> malicious (TP), ben -> malicious (FP)
    rep = evals.run_eval(_two_case_dir(tmp_path),
                         analyze_fn=_fake_analyze(["likely-malicious", "likely-malicious"]))
    s = rep["summary"]
    assert s["cases_passed"] == 1 and s["failed_cases"] == ["ben"]
    assert s["accuracy"] == 0.5
    assert s["malicious"]["precision"] == 0.5 and s["malicious"]["recall"] == 1.0
    assert s["false_positive_rate"] == 1.0
    assert s["total_cost_usd"] == 1.0 and s["total_tokens"] == 200
    assert s["cost_basis"] == ["reported"]
    assert s["tier2_agreement"] is None
    assert "FAIL" in evals.format_report(rep)


def test_repeat_reports_verdict_stability(tmp_path):
    d = _two_case_dir(tmp_path)
    rep = evals.run_eval(d, names=["mal"], repeat=3, analyze_fn=_fake_analyze(
        ["likely-malicious", "likely-malicious", "needs-review"]))
    c = rep["cases"][0]
    assert len(c["runs"]) == 3
    assert c["stability"] == pytest.approx(0.6667, abs=1e-3)
    assert c["modal_verdict"] == "likely-malicious"
    assert not c["passed"]          # one repetition disagreed


def test_analyze_exception_is_reported_not_hidden(tmp_path):
    def boom(files, **kw):
        raise RuntimeError("kaboom")
    rep = evals.run_eval(_two_case_dir(tmp_path), analyze_fn=boom)
    assert rep["summary"]["run_errors"] == 2 and rep["summary"]["cases_failed"] == 2
    assert "kaboom" in rep["cases"][0]["runs"][0]["error"]


def test_invalid_case_fails_loudly(tmp_path):
    d = tmp_path / "bad"
    d.mkdir()
    (d / "a.log").write_text("x")
    (d / "expected.json").write_text("{not json")
    rep = evals.run_eval(str(tmp_path), analyze_fn=_fake_analyze([]))
    assert rep["cases"][0]["passed"] is False
    assert "expected.json" in rep["cases"][0]["runs"][0]["error"]


def test_unknown_case_name_and_missing_dir(tmp_path):
    with pytest.raises(FileNotFoundError):
        evals.run_eval(str(tmp_path / "nope"))
    with pytest.raises(FileNotFoundError):
        evals.run_eval(_two_case_dir(tmp_path), names=["ghost"])


def test_real_offline_run_on_shipped_cases():
    rep = evals.run_eval(CASES, names=["apt_chain_web01", "stale_credential_activesync"],
                         llm="off", trace=False)
    assert rep["summary"]["cases_passed"] == 2
    assert rep["config"]["backbone"].startswith("none")


def test_cli_exit_code_and_json(tmp_path, capsys):
    out = tmp_path / "rep.json"
    # offline the requires_llm cases are skipped (reported, not failed) -> exit 0
    rc = main(["eval", "--cases", CASES, "--llm", "off", "--no-trace", "--json", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["schema"] == "bastion.eval/1" and data["summary"]["cases_failed"] == 0
    assert len(data["summary"]["skipped_requires_llm"]) == 5
    assert "accuracy" in capsys.readouterr().out
    rc = main(["eval", "--cases", CASES, "--case", "apt_chain_web01", "--no-trace"])
    assert rc == 0
    assert main(["eval", "--cases", str(tmp_path / "missing")]) == 2
