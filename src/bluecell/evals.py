# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Eval suite runner: labelled cases -> analyze() -> scored report.

A case is a directory ``evals/cases/<name>/`` holding log files plus
``expected.json``::

    {"description": "...",
     "verdict": "likely-malicious" | "likely-benign" | "needs-review",
     "tier2": "confirmed" | "dismissed" | null,
     "must_mention": ["substring", ...],        # optional, case-insensitive
     "must_not_mention": ["substring", ...],    # optional
     "min_incidents": 0}                        # optional

Scoring per run:
- verdict   : the headline verdict (incidents[0] after BlueCell's own ordering)
              equals ``verdict``. No incidents at all counts as "likely-benign".
- tier2     : only scored when expected ``tier2`` is set AND a Tier-2 *agent*
              verdict exists for the headline incident (rule-only Tier-2 is
              reported as ``tier2_rule`` but never scored, matching how the
              analyzer itself treats it). Otherwise "n/a".
- mentions  : over the rendered Markdown report + swarm findings + AI analysis.
- min_incidents.

A case passes only if every repetition passes. Aggregates: accuracy,
precision/recall/false-positive rate for the malicious class, Tier-2 agreement,
mean duration, total cost/tokens (from the run trace), and per-case verdict
stability (share of repetitions that agree with the most common verdict).
"""
from __future__ import annotations

import json
import os
import time
from collections import Counter
from datetime import datetime, timezone

SCHEMA = "bluecell.eval/1"
VERDICTS = ("likely-malicious", "likely-benign", "needs-review")
TIER2 = ("confirmed", "dismissed")
LOG_EXTS = (".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".syslog")
DEFAULT_CASES = os.path.join("evals", "cases")
NO_INCIDENT_VERDICT = "likely-benign"


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------
def validate_expected(exp) -> list:
    """Problems with an expected.json payload ([] when valid)."""
    if not isinstance(exp, dict):
        return ["expected.json must be a JSON object"]
    probs = []
    if exp.get("verdict") not in VERDICTS:
        probs.append(f"verdict must be one of {VERDICTS}, got {exp.get('verdict')!r}")
    if exp.get("tier2") not in TIER2 + (None,):
        probs.append(f"tier2 must be one of {TIER2} or null, got {exp.get('tier2')!r}")
    for key in ("must_mention", "must_not_mention"):
        v = exp.get(key, [])
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            probs.append(f"{key} must be a list of strings")
    mi = exp.get("min_incidents", 0)
    if not isinstance(mi, int) or isinstance(mi, bool) or mi < 0:
        probs.append("min_incidents must be a non-negative integer")
    return probs


def case_files(case_dir: str) -> list:
    """Log files of a case (expected.json and docs excluded), recursively."""
    out = []
    for root, dirs, files in os.walk(case_dir):
        dirs.sort()
        for f in sorted(files):
            if f == "expected.json" or f.startswith("."):
                continue
            if os.path.splitext(f)[1].lower() in LOG_EXTS:
                out.append(os.path.join(root, f))
    return out


def load_cases(cases_dir: str, names=None) -> list:
    if not os.path.isdir(cases_dir):
        raise FileNotFoundError(f"cases directory not found: {cases_dir}")
    wanted = set(names or [])
    cases = []
    for name in sorted(os.listdir(cases_dir)):
        d = os.path.join(cases_dir, name)
        exp_path = os.path.join(d, "expected.json")
        if wanted and name not in wanted:
            continue
        files = case_files(d)
        if not os.path.isfile(exp_path):
            if files:  # logs without a label file (e.g. expected.jsno): invalid, not skipped
                cases.append({"name": name, "dir": d, "files": files, "expected": {},
                              "problems": [f"no expected.json but {len(files)} log file(s) "
                                           "present (misnamed label file?)"]})
            continue
        try:
            with open(exp_path, encoding="utf-8") as fh:
                exp = json.load(fh)
            probs = validate_expected(exp)
            if not isinstance(exp, dict):  # keep the problem, but callers need a dict
                exp = {}
        except ValueError as exc:
            exp, probs = {}, [f"expected.json is not valid JSON: {exc}"]
        cases.append({"name": name, "dir": d, "files": files,
                      "expected": exp, "problems": probs})
    missing = wanted - {c["name"] for c in cases}
    if missing:
        raise FileNotFoundError(f"case(s) not found in {cases_dir}: {', '.join(sorted(missing))}")
    if not cases:  # an empty suite must not pass a CI gate vacuously
        raise FileNotFoundError(f"no eval cases found in {cases_dir}")
    return cases


# ---------------------------------------------------------------------------
# Observing + scoring one result
# ---------------------------------------------------------------------------
def _decision(status):
    if status == "escalated":
        return "confirmed"
    if status == "dismissed":
        return "dismissed"
    return None


def observe(result: dict) -> dict:
    """The facts the scorer needs from one analyze() result."""
    incs = result.get("incidents") or []
    top = incs[0] if incs else None
    verdict = ((top.get("verdict") or {}).get("level") if top else NO_INCIDENT_VERDICT)
    tier2 = tier2_rule = None
    swarm = result.get("swarm") or {}
    if top:
        for f in swarm.get("findings") or []:
            if f.get("tier") != 2 or f.get("incident_id") != top.get("id"):
                continue
            if f.get("origin") == "agent":
                tier2 = _decision(f.get("status"))
            elif tier2_rule is None:
                tier2_rule = _decision(f.get("status"))
    try:
        from .report import render_markdown
        text = render_markdown(result)
    except Exception:
        text = ""
    text += "\n" + json.dumps(swarm.get("findings") or [], default=str)
    text += "\n" + json.dumps(result.get("ai_analysis") or {}, default=str)
    meta = result.get("meta") or {}
    trace = meta.get("trace") or {}
    return {"verdict": verdict, "tier2": tier2, "tier2_rule": tier2_rule,
            "incidents": len(incs), "text": text,
            "run_id": trace.get("run_id"),
            "cost_usd": trace.get("total_cost_usd"),  # None = unknown, never a fake 0
            "cost_unknown_calls": trace.get("cost_unknown_calls") or 0,
            "cost_basis": trace.get("cost_basis") or [],
            "tokens": (trace.get("tokens") or {}).get("total", 0),
            "llm_calls": trace.get("llm_calls", 0),
            "tool_calls": trace.get("tool_calls", 0),
            "backbone": meta.get("backbone")}


def score(expected: dict, obs: dict) -> dict:
    """Score one observation. Each check is "pass", "fail" or "n/a"."""
    checks, failures = {}, []
    exp_v = expected.get("verdict")
    checks["verdict"] = "pass" if obs.get("verdict") == exp_v else "fail"
    if checks["verdict"] == "fail":
        failures.append(f"verdict {obs.get('verdict')} != expected {exp_v}")

    exp_t2 = expected.get("tier2")
    if exp_t2 is None or obs.get("tier2") is None:
        checks["tier2"] = "n/a"
    else:
        checks["tier2"] = "pass" if obs["tier2"] == exp_t2 else "fail"
        if checks["tier2"] == "fail":
            failures.append(f"Tier-2 agent {obs['tier2']} != expected {exp_t2}")

    low = (obs.get("text") or "").lower()
    missing = [m for m in expected.get("must_mention") or [] if m.lower() not in low]
    present = [m for m in expected.get("must_not_mention") or [] if m.lower() in low]
    checks["must_mention"] = ("n/a" if not expected.get("must_mention")
                              else "fail" if missing else "pass")
    checks["must_not_mention"] = ("n/a" if not expected.get("must_not_mention")
                                  else "fail" if present else "pass")
    if missing:
        failures.append(f"missing mention(s): {missing}")
    if present:
        failures.append(f"forbidden mention(s): {present}")

    mi = expected.get("min_incidents")
    if mi is None:
        checks["min_incidents"] = "n/a"
    else:
        checks["min_incidents"] = "pass" if obs.get("incidents", 0) >= mi else "fail"
        if checks["min_incidents"] == "fail":
            failures.append(f"{obs.get('incidents', 0)} incident(s) < min {mi}")
    return {"checks": checks, "failures": failures,
            "passed": not any(v == "fail" for v in checks.values())}


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
def _ratio(a, b):
    return round(a / b, 4) if b else None


def aggregate(cases: list) -> dict:
    """Aggregate metrics over every run of every case (repetitions included)."""
    runs = [(c, r) for c in cases for r in c["runs"] if not r.get("error")]
    errored = [(c, r) for c in cases for r in c["runs"] if r.get("error")]
    errors = len(errored)
    tp = fp = fn = tn = 0
    correct = t2_n = t2_ok = 0
    for c, r in runs:
        exp_mal = c["expected"].get("verdict") == "likely-malicious"
        pred_mal = r["verdict"] == "likely-malicious"
        tp += exp_mal and pred_mal
        fp += (not exp_mal) and pred_mal
        fn += exp_mal and not pred_mal
        tn += (not exp_mal) and not pred_mal
        correct += r["verdict"] == c["expected"].get("verdict")
        if r["checks"]["tier2"] != "n/a":
            t2_n += 1
            t2_ok += r["checks"]["tier2"] == "pass"
    # A crashed run is a wrong answer: a missed malicious case is a false negative;
    # it is in no tp/fp/tn cell and in no correct count, so it lowers accuracy.
    fn += sum(1 for c, _ in errored if c["expected"].get("verdict") == "likely-malicious")
    durations = [r["duration_ms"] for _, r in runs]
    costs = [r["cost_usd"] for _, r in runs if r.get("cost_usd") is not None]
    # Runs with any unknown-cost call: total is the known partial sum (">= x"),
    # or None (n/a) when no run has a known cost at all.
    cost_unknown_runs = sum(1 for _, r in runs
                            if r.get("cost_usd") is None or r.get("cost_unknown_calls"))
    bases = sorted({b for _, r in runs for b in r.get("cost_basis") or []})
    return {
        "cases": len(cases),
        "cases_passed": sum(1 for c in cases if c["passed"]),
        "cases_failed": sum(1 for c in cases if not c["passed"]),
        "failed_cases": [c["name"] for c in cases if not c["passed"]],
        "runs": len(runs) + errors,
        "run_errors": errors,
        "accuracy": _ratio(correct, len(runs) + errors),
        "malicious": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                      "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn)},
        "false_positive_rate": _ratio(fp, fp + tn),
        "tier2_agreement": _ratio(t2_ok, t2_n),
        "tier2_scored_runs": t2_n,
        "mean_duration_ms": round(sum(durations) / len(durations), 1) if durations else None,
        "total_cost_usd": (round(sum(costs), 6) if costs or not cost_unknown_runs else None),
        "cost_unknown_runs": cost_unknown_runs,
        "cost_basis": bases,
        "total_tokens": sum(r.get("tokens") or 0 for _, r in runs),
        "llm_calls": sum(r.get("llm_calls") or 0 for _, r in runs),
        "tool_calls": sum(r.get("tool_calls") or 0 for _, r in runs),
        "mean_verdict_stability": (round(sum(c["stability"] for c in cases) / len(cases), 4)
                                   if cases else None),
    }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_case(case: dict, *, repeat: int = 1, analyze_fn=None, backbone=None,
             use_llm: bool = False, trace=None, options: dict | None = None) -> dict:
    """Analyze one case ``repeat`` times. Only the case's log files are passed
    (never expected.json); the run cache is off so every repetition is a real
    run. ``options`` are extra analyze() keyword arguments (orchestration,
    votes, tier1_model, commander limits)."""
    if analyze_fn is None:
        from .analyzer import analyze as analyze_fn
    runs = []
    for i in range(max(1, repeat)):
        rec = {"rep": i + 1}
        if case["problems"]:
            rec.update(error="invalid expected.json: " + "; ".join(case["problems"]))
        elif not case["files"]:
            rec.update(error="case has no log files")
        else:
            t0 = time.perf_counter()
            try:
                result = analyze_fn(case["files"], backbone=backbone, use_llm=use_llm,
                                    trace=trace, **dict(options or {}, cache="off"))
                obs = observe(result)
            except Exception as exc:
                rec.update(error=f"{type(exc).__name__}: {exc}")
                obs = None
            rec["duration_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            if obs is not None:
                sc = score(case["expected"], obs)
                obs.pop("text", None)
                rec.update(obs, **sc)
        if rec.get("error"):
            rec.update(passed=False, verdict=None, checks={}, failures=[rec["error"]])
        runs.append(rec)
    verdicts = [r["verdict"] for r in runs if r.get("verdict")]
    modal = Counter(verdicts).most_common(1)
    return {
        "name": case["name"],
        "description": case["expected"].get("description", ""),
        "expected": {k: case["expected"].get(k) for k in
                     ("verdict", "tier2", "must_mention", "must_not_mention", "min_incidents")},
        "files": [os.path.relpath(f, case["dir"]) for f in case["files"]],
        "runs": runs,
        "passed": all(r["passed"] for r in runs),
        "pass_rate": _ratio(sum(1 for r in runs if r["passed"]), len(runs)),
        "stability": _ratio(modal[0][1], len(runs)) if modal else 0.0,
        "modal_verdict": modal[0][0] if modal else None,
    }


def run_eval(cases_dir: str = DEFAULT_CASES, *, names=None, repeat: int = 1,
             llm: str = "off", backbone=None, analyze_fn=None, trace=None,
             progress=None, options: dict | None = None) -> dict:
    """Run every case and return the report dict (schema ``bluecell.eval/1``)."""
    cases = load_cases(cases_dir, names)
    use_llm = llm != "off" and backbone is not None
    results = []
    for c in cases:
        r = run_case(c, repeat=repeat, analyze_fn=analyze_fn, backbone=backbone,
                     use_llm=use_llm, trace=trace, options=options)
        results.append(r)
        if progress:
            progress(r)
    return {
        "schema": SCHEMA,
        "generated": datetime.now(timezone.utc).isoformat(),
        "config": {"cases_dir": cases_dir, "llm": llm,
                   "backbone": (backbone.resolved if backbone else "none (rules)"),
                   "model": getattr(backbone, "model", None), "repeat": repeat,
                   "options": {k: v for k, v in (options or {}).items() if v is not None}},
        "summary": aggregate(results),
        "cases": results,
    }


# ---------------------------------------------------------------------------
# Text output
# ---------------------------------------------------------------------------
_SHORT = {"likely-malicious": "malicious", "likely-benign": "benign",
          "needs-review": "review", None: "-"}


def _pct(v):
    return "n/a" if v is None else f"{v * 100:.0f}%"


def format_report(report: dict) -> str:
    cfg, s = report["config"], report["summary"]
    rows = [("case", "expected", "got", "tier2 exp/got", "mentions", "stab", "result")]
    for c in report["cases"]:
        last = c["runs"][-1]
        got = ",".join(sorted({_SHORT.get(r.get("verdict"), r.get("verdict")) for r in c["runs"]}))
        t2 = (f"{c['expected'].get('tier2') or '-'}/"
              f"{last.get('tier2') or ('rule:' + last['tier2_rule'] if last.get('tier2_rule') else '-')}")
        men = "fail" if any((r.get("checks") or {}).get("must_mention") == "fail"
                            or (r.get("checks") or {}).get("must_not_mention") == "fail"
                            for r in c["runs"]) else "ok"
        rows.append((c["name"], _SHORT.get(c["expected"].get("verdict")), got, t2, men,
                     _pct(c["stability"]), "PASS" if c["passed"] else "FAIL"))
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    out = [f"BlueCell eval: {len(report['cases'])} case(s), backbone={cfg['backbone']}, "
           f"repeat={cfg['repeat']}", ""]
    for i, r in enumerate(rows):
        out.append("  ".join(str(v).ljust(widths[j]) for j, v in enumerate(r)))
        if i == 0:
            out.append("  ".join("-" * w for w in widths))
    for c in report["cases"]:
        for r in c["runs"]:
            if r["failures"]:
                out.append(f"  - {c['name']} (rep {r['rep']}): " + "; ".join(r["failures"]))
                break
    m = s["malicious"]
    out += ["",
            f"passed {s['cases_passed']}/{s['cases']} cases"
            + (f" (failed: {', '.join(s['failed_cases'])})" if s["failed_cases"] else ""),
            f"accuracy {_pct(s['accuracy'])} · malicious precision {_pct(m['precision'])} "
            f"recall {_pct(m['recall'])} · false-positive rate {_pct(s['false_positive_rate'])}"]
    if s["run_errors"]:
        out.append(f"{s['run_errors']} run error(s) of {s['runs']}, counted as wrong")
    out += [f"Tier-2 agreement {_pct(s['tier2_agreement'])} over {s['tier2_scored_runs']} scored run(s)"
            + ("" if s["tier2_scored_runs"] else " (no Tier-2 agent verdicts: rules mode)"),
            f"mean duration {s['mean_duration_ms']} ms · tokens {s['total_tokens']} · "
            f"LLM calls {s['llm_calls']} · tool calls {s['tool_calls']} · "
            "cost " + ("n/a" if s["total_cost_usd"] is None else
                       f"{'>= ' if s['cost_unknown_runs'] else ''}${s['total_cost_usd']:.4f}")
            + (f" ({'/'.join(s['cost_basis'])})" if s["cost_basis"] else ""),
            f"mean verdict stability {_pct(s['mean_verdict_stability'])}"]
    return "\n".join(out)
