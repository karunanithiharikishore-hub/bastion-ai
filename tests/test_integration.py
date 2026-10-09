"""Cross-feature integration tests: run cache x tracing x evals x injection
defenses x Incident Commander x Tier-2 voting. No real model calls: every
backbone here is a fake."""
import json
import os
import shutil

import pytest

from conftest import SAMPLES
from bluecell import evals
from bluecell.ingest import ingest_paths

ROOT = os.path.join(os.path.dirname(__file__), "..")
CASES = os.path.join(ROOT, "evals", "cases")


# ---------------------------------------------------------------------------
# Evals: the answer key is never ingested as an event
# ---------------------------------------------------------------------------
def test_case_dir_walk_skips_expected_json():
    case = os.path.join(CASES, "vuln_scanner_web")
    walked = ingest_paths([case])
    files = evals.case_files(case)
    assert all(os.path.basename(f) != "expected.json" for f in files)
    assert len(walked) == len(ingest_paths(files))
    assert not any("zgrab UA" in (e.message or "") and e.source == "edr" for e in walked)


def test_expected_json_that_is_a_log_is_still_ingested(tmp_path):
    # Only an eval label (verdict = a BlueCell verdict level) is skipped.
    (tmp_path / "expected.json").write_text(json.dumps(
        {"timestamp": "2026-09-26T09:00:00Z", "source": "edr", "host": "h1",
         "process": "cmd.exe", "message": "process start"}))
    assert len(ingest_paths([str(tmp_path)])) == 1


def test_eval_runner_passes_only_log_files(tmp_path):
    seen = []

    def fake_analyze(paths, **kw):
        seen.extend(paths)
        return {"incidents": [], "meta": {}, "swarm": None}
    evals.run_eval(CASES, names=["vuln_scanner_web"], analyze_fn=fake_analyze, trace=False)
    assert seen and all(os.path.isfile(p) for p in seen)
    assert not any(os.path.basename(p) == "expected.json" for p in seen)


def test_tests_never_write_to_real_home():
    home = os.path.join(os.path.expanduser("~"), ".bluecell")
    for var in ("BLUECELL_CACHE_DIR", "BLUECELL_RUNS_DIR"):
        assert os.environ.get(var)
        assert not os.path.abspath(os.environ[var]).startswith(home)
    from bluecell import cache, tracing
    assert not cache.cache_dir().startswith(home)
    assert not tracing.runs_dir().startswith(home)


# ---------------------------------------------------------------------------
# Run cache x tracing
# ---------------------------------------------------------------------------
def test_cache_hit_is_traced_and_links_the_original_run(tmp_path, monkeypatch):
    from test_repeatability import FakeBackbone
    from bluecell import analyzer, tracing
    from bluecell.report import render_markdown
    monkeypatch.setenv("BLUECELL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("BLUECELL_RUNS_DIR", str(tmp_path / "runs"))
    bb = FakeBackbone()
    first = analyzer.analyze([SAMPLES], backbone=bb, intel_store=None, cache="use")
    assert first["meta"]["cache"] == "miss (stored)", first["meta"]["cache"]
    assert first["meta"]["trace"]["llm_calls"] >= 1
    calls = bb.calls
    second = analyzer.analyze([SAMPLES], backbone=bb, intel_store=None, cache="use")
    assert bb.calls == calls
    assert second["meta"]["cache"] == "hit"
    assert second["meta"]["original_run_id"] == first["meta"]["trace"]["run_id"]
    assert second["meta"]["trace"]["run_id"] != first["meta"]["trace"]["run_id"]
    assert second["meta"]["trace"]["llm_calls"] == 0
    listed = {r["run_id"]: r for r in tracing.list_runs()}
    assert listed[second["meta"]["trace"]["run_id"]]["cache"] == "hit"
    assert "Served from the run cache" in render_markdown(second)


# ---------------------------------------------------------------------------
# Prompt-injection defenses x run cache x Tier-2 voting
# ---------------------------------------------------------------------------
def test_cache_key_covers_injection_defenses(monkeypatch):
    from bluecell import cache as run_cache
    from bluecell.agents import injection
    before = run_cache.prompt_fingerprint()
    monkeypatch.setattr(injection, "BOUNDARY_INSTRUCTION", "something else")
    assert run_cache.prompt_fingerprint() != before


def _injected_case(tmp_path):
    dst = tmp_path / "injection_attack_dismiss"
    shutil.copytree(os.path.join(CASES, "injection_attack_dismiss"), dst)
    os.remove(dst / "expected.json")
    return str(dst)


class _DismissModel:
    """Every Tier-2 vote dismisses every incident. ``address`` = whether the
    rationale discusses the injection and cites the flagged events (what the
    submit_verdict guard requires)."""
    resolved = "api"
    model = "fake"
    temperature = 0.0
    sampling = "temperature=0"

    def __init__(self, incidents, address):
        self.incidents, self.address = incidents, address
        self.tier2_runs = 0
        self.rejections = 0

    def complete(self, prompt, system=None, max_tokens=0):
        return json.dumps({"verdict": "needs-review", "confidence": 0.5, "headline": "x"})

    def messages(self, body):
        from bluecell.agents.injection import is_flagged
        msgs = body["messages"]
        last = msgs[-1]["content"]
        if isinstance(last, list) and last and last[0].get("type") == "tool_result":
            self.rejections += sum("verdict rejected" in r["content"] for r in last)
            return {"content": [{"type": "text", "text": "done"}]}
        if "Tier-2 SOC Analyst" not in body["system"]:
            return {"content": [{"type": "text", "text": "nothing to file"}]}
        self.tier2_runs += 1
        uses = []
        for i, inc in enumerate(self.incidents):
            flagged = [e.event_id for e in inc.events if is_flagged(e)]
            if self.address:
                rationale = ("The prompt injection attempt in the logs is attacker text "
                             "and does not change the call; the activity is approved work.")
                evidence = (flagged or [inc.events[0].event_id])[:3]
            else:
                rationale, evidence = "approved maintenance", [inc.events[0].event_id]
            uses.append({"type": "tool_use", "id": f"v{i}", "name": "submit_verdict",
                         "input": {"incident_id": inc.id, "decision": "dismissed",
                                   "confidence": 0.9, "rationale": rationale,
                                   "evidence": evidence}})
        return {"content": uses}


def _incidents_for(path):
    from bluecell.pipeline import normalize, map_attack, correlate
    from bluecell.agents import injection
    events = normalize(ingest_paths([path]))
    map_attack(events)
    injection.tag_events(events)
    return correlate(events, window_minutes=60)


def test_every_vote_is_guarded_and_split_leaves_rules_needs_review(tmp_path):
    from bluecell import analyzer
    path = _injected_case(tmp_path)
    model = _DismissModel(_incidents_for(path), address=False)
    result = analyzer.analyze([path], backbone=model, intel_store=None, votes=3,
                              trace=False)
    assert model.tier2_runs == 3 and model.rejections >= 3    # each vote bounced
    senior = next(r for r in result["swarm"]["agent_runs"] if r["agent"] == "soc2-lead")
    assert senior["votes"]["k"] == 3
    assert all(i["verdict"]["level"] != "likely-benign" for i in result["incidents"])


def test_unanimous_vote_dismissal_of_injected_incident_is_downgraded(tmp_path):
    from bluecell import analyzer
    from bluecell.report import render_markdown
    path = _injected_case(tmp_path)
    model = _DismissModel(_incidents_for(path), address=True)
    result = analyzer.analyze([path], backbone=model, intel_store=None, votes=3)
    assert model.rejections == 0
    injected = [b for b in result["incidents"]
                if any("injection:suspected" in (e.get("tags") or []) for e in b["events"])]
    assert injected
    for b in injected:
        v = b["verdict"]
        assert v["decided_by"] == "tier2-agent"
        assert v["level"] == "needs-review" and v["injection_note"]
        assert v["votes"]["dismissed"] == 3 and v["votes"]["agreement"] == 1.0
    md = render_markdown(result)
    for section in ("Prompt-injection attempts detected in logs", "Run cost & trace"):
        assert section in md
