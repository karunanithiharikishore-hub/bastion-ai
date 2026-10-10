"""Quick vs deep analysis modes. Offline: fake backbones only."""
import json
import os
import shutil

from conftest import SAMPLES, BENIGN_SAMPLES
from bastion import analyzer, cache as run_cache, cli
from bastion.web.server import _State
from test_injection import CASES
from test_repeatability import FakeBackbone, _events


class AnalystBackbone(FakeBackbone):
    """Answers every analyst call with one verdict; counts agent (messages) calls."""
    def __init__(self, verdict):
        super().__init__()
        self.verdict, self.agent_calls = verdict, 0

    def complete(self, prompt, system=None, max_tokens=1500):
        self.calls += 1
        return json.dumps({"verdict": self.verdict, "corrected_verdict": self.verdict,
                           "agree": True, "confidence": 0.8, "headline": "analyst says so",
                           "notes": "ok"})

    def messages(self, body):
        self.agent_calls += 1
        return super().messages(body)


def _run(path, bb, mode="quick", **kw):
    return analyzer.analyze([path], backbone=bb, mode=mode, trace=False, **kw)


def test_quick_runs_no_swarm_and_applies_analyst_verdict():
    bb = AnalystBackbone("likely-benign")
    res = _run(BENIGN_SAMPLES, bb)
    assert bb.agent_calls == 0 and res["swarm"] is None and res["meta"]["mode"] == "quick"
    assert res["ai_analysis"]["final_verdict"] == "likely-benign"
    v = res["incidents"][0]["verdict"]
    assert v["decided_by"] == "ai-analyst" and v["headline"].startswith("AI analyst")


def test_quick_malicious_overrides_rules():
    res = _run(SAMPLES, AnalystBackbone("likely-malicious"))
    assert all(b["verdict"]["level"] == "likely-malicious" and
               b["verdict"]["decided_by"] == "ai-analyst" for b in res["incidents"])


def test_quick_analyst_verdict_applies_to_top_incident_only():
    paths = [SAMPLES, BENIGN_SAMPLES]          # two incidents in one case
    run = lambda bb: analyzer.analyze(paths, backbone=bb, mode="quick", trace=False)
    rules = run(None)
    top = max(rules["incidents"], key=lambda b: b["score"])
    other = next(b for b in rules["incidents"] if b["id"] != top["id"])
    res = run(AnalystBackbone("likely-benign"))
    by_id = {b["id"]: b for b in res["incidents"]}
    assert len(by_id) == 2
    assert by_id[top["id"]]["verdict"]["level"] == "likely-benign"
    assert by_id[top["id"]]["verdict"]["decided_by"] == "ai-analyst"
    assert by_id[other["id"]]["verdict"]["level"] == other["verdict"]["level"]
    assert "decided_by" not in by_id[other["id"]]["verdict"]


def test_quick_without_backbone_is_rules_only():
    res = _run(SAMPLES, None)
    assert res["ai_analysis"] is None and res["swarm"] is None
    assert all("decided_by" not in b["verdict"] for b in res["incidents"])


def test_quick_injection_incident_cannot_be_benign(tmp_path):
    dst = tmp_path / "inj"
    shutil.copytree(os.path.join(CASES, "injection_attack_dismiss"), dst)
    (dst / "expected.json").unlink()
    res = _run(str(dst), AnalystBackbone("likely-benign"))
    assert res["ai_analysis"].get("injection_override")
    assert all(b["verdict"]["level"] != "likely-benign" for b in res["incidents"])


def test_deep_still_runs_swarm():
    bb = AnalystBackbone("needs-review")
    res = _run(SAMPLES, bb, mode="deep")
    assert bb.agent_calls > 0 and res["swarm"] and res["meta"]["mode"] == "deep"


def test_cache_key_differs_by_mode(tmp_path):
    keys = {}
    for m in ("quick", "deep"):
        res = _run(SAMPLES, AnalystBackbone("likely-malicious"), mode=m, cache="use")
        keys[m] = res["meta"]["cache_key"]
    assert keys["quick"] != keys["deep"]
    again = _run(SAMPLES, AnalystBackbone("likely-malicious"), mode="quick", cache="use")
    assert again["meta"]["mode"] == "quick" and "hit" in again["meta"]["cache"]


def test_bad_mode_rejected():
    import pytest
    with pytest.raises(ValueError):
        analyzer.analyze([SAMPLES], mode="fast", trace=False)


def test_web_upload_mode(monkeypatch):
    state = _State([SAMPLES], window=120, llm_mode="off", model="x", intel_db=None, mode="quick")
    seen = []
    real = analyzer.analyze
    monkeypatch.setattr("bastion.web.server.analyze",
                        lambda *a, **k: (seen.append(k["mode"]), real(*a, trace=False, **k))[1])
    files = [{"name": "a.log", "content": open(os.path.join(SAMPLES, os.listdir(SAMPLES)[0])).read()}]
    try:
        assert state.run_on_uploads(files)["meta"]["mode"] == "quick"      # server default
        assert state.run_on_uploads(files, mode="deep")["meta"]["mode"] == "deep"
    finally:
        state.close()
    assert seen == ["quick", "deep"]


def test_cli_mode_flag(capsys):
    p = cli.build_parser()
    assert p.parse_args(["analyze", SAMPLES]).mode == "deep"
    assert p.parse_args(["analyze", SAMPLES, "--mode", "quick"]).mode == "quick"
    assert p.parse_args(["serve", SAMPLES]).mode == "quick"
    assert p.parse_args(["serve", SAMPLES, "--mode", "deep"]).mode == "deep"
    assert cli.main(["analyze", SAMPLES, "--llm", "off", "--no-trace", "--no-cache",
                     "--mode", "quick", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["meta"]["mode"] == "quick"
