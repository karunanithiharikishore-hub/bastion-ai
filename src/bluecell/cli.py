# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BlueCell command-line interface.

Commands:
  analyze   Run the full pipeline + agent swarm and write a report.
  serve     Launch the local web dashboard.
  intel     Manage the threat-intel knowledge base (add / import / stats / search).
  roster    Show the blue-team agent swarm roster.
  plan      Offline cost plan (processes, turn budget) for analyzing some logs.
  info      Show environment + backbone availability + authorship.
  eval      Run the labelled eval suite and score verdicts.
  runs      List traced runs (cost, tokens, duration) or show one span tree.
"""
from __future__ import annotations

import argparse
import atexit
import signal
import json
import os
import sys
import threading

from . import __version__, provenance
from .analyzer import analyze
from .intel import IntelStore
from .llm import LLMBackbone, BackboneUnavailable
from .report import render_markdown, render_json
from .ingest.loader import _SOURCE_HINTS, _canon
from .ingest.parsers import STRUCTURED_PARSERS

# Every source label the loader can assign; --source is validated against it.
_SOURCE_CHOICES = sorted({_canon(h) for h in _SOURCE_HINTS} | set(STRUCTURED_PARSERS))


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {value!r}")
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {n}")
    return n


def _budget_seconds(value: str) -> int:
    from .agents.commander import MIN_WORKER_SECONDS
    n = _positive_int(value)
    if n <= MIN_WORKER_SECONDS:  # a budget of exactly one worker's minimum leaves no room to plan
        raise argparse.ArgumentTypeError(f"must be more than {MIN_WORKER_SECONDS} (a worker needs "
                                         f"{MIN_WORKER_SECONDS}s), got {n}")
    return n


_MAX_WINDOW_MIN = 10 * 366 * 24 * 60  # same bound as web/server.py; timedelta overflows above it


def _window(value: str) -> int:
    n = _positive_int(value)
    if n > _MAX_WINDOW_MIN:
        raise argparse.ArgumentTypeError(f"window must be at most {_MAX_WINDOW_MIN} minutes, got {n}")
    return n


def _port(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {value!r}")
    if not 1 <= n <= 65535:
        raise argparse.ArgumentTypeError(f"port must be 1-65535, got {n}")
    return n


def _make_backbone(mode: str, model: str):
    if mode == "off":
        return None
    try:
        return LLMBackbone(mode=mode, model=model)
    except BackboneUnavailable as exc:
        print(f"[bluecell] LLM backbone unavailable ({exc}); "
              f"using deterministic storyline.", file=sys.stderr)
        return None


def cmd_analyze(args) -> int:
    for p in args.paths:
        if not os.path.exists(p):
            print(f"[bluecell] path not found: {p}", file=sys.stderr)
            return 2
    out_dir = os.path.dirname(os.path.abspath(args.output)) if args.output else ""
    if out_dir and not os.path.isdir(out_dir):
        print(f"[bluecell] output directory not found: {out_dir}", file=sys.stderr)
        return 2
    backbone = _make_backbone(args.llm, args.model)
    intel = IntelStore(args.intel_db) if args.intel_db else IntelStore()
    result = analyze(
        args.paths,
        source_override=args.source,
        window_minutes=args.window,
        max_incidents=args.max_incidents,
        backbone=backbone,
        intel_store=intel,
        run_agents=not args.no_agents,
        use_llm=(args.llm != "off"),
        cache=("off" if args.no_cache else "refresh" if args.refresh else "use"),
        votes=args.votes,
        tier1_model=args.model_tier1,
        skip_idle_tier1=not args.all_tier1,
        trace=(False if args.no_trace else None),
        orchestration=args.orchestration,
        max_agents=args.max_agents,
        max_commander_turns=args.max_commander_turns,
        budget_seconds=args.budget_seconds,
    )
    output = render_json(result) if args.format == "json" else render_markdown(result)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output)
        except OSError as exc:
            print(f"[bluecell] cannot write report: {exc}", file=sys.stderr)
            return 2
        print(f"[bluecell] wrote {args.format} report -> {args.output}")
        print(f"[bluecell] {len(result['incidents'])} incident(s), "
              f"{result['meta']['events_ingested']} events, "
              f"backbone={result['meta']['backbone']}")
        _print_cache(result)
        _print_verdicts(result)
        _print_ai(result)
    else:
        print(output)
    return 0


_VERDICT_ICON = {"likely-malicious": "🔴 LIKELY REAL ATTACK",
                 "likely-benign": "🟢 LIKELY BENIGN / NOISE",
                 "needs-review": "🟡 NEEDS REVIEW"}


def _print_verdicts(result) -> None:
    """Print the per-incident verdict to the terminal so the real-vs-noise call
    is visible without opening the report file."""
    incs = result.get("incidents") or []
    if not incs:
        print("[bluecell] verdict: no incidents crossed the threshold.")
        return
    for inc in incs[:5]:
        v = inc.get("verdict") or {}
        s = inc["storyline"]["structured"]
        icon = _VERDICT_ICON.get(v.get("level"), (v.get("level") or "?").upper())
        print(f"[bluecell] {s['incident_id']}: {icon} "
              f"({round(v.get('confidence', 0) * 100)}%): {v.get('headline', '')}")
        if v.get("overrides_rules"):
            rv = v.get("rule_verdict") or {}
            rule_icon = _VERDICT_ICON.get(rv.get("level"), (rv.get("level") or "?").upper())
            print(f"[bluecell]   (overruled the rule-based score: {rule_icon} "
                  f"{round((rv.get('confidence') or 0) * 100)}%)")


def _print_cache(result) -> None:
    meta = result.get("meta") or {}
    status = meta.get("cache")
    if not status or status.startswith("n/a"):
        return
    if status == "hit":
        orig = (meta.get("original_timing_ms") or {}).get("total")
        print(f"[bluecell] cache: hit (stored {meta.get('cached_at')}; original run "
              f"{round((orig or 0) / 1000, 1)} s). Use --refresh to re-run.")
    else:
        print(f"[bluecell] cache: {status}")


def cmd_plan(args) -> int:
    """Offline: how many claude processes / model turns a run would use."""
    from .ingest import ingest_paths
    from .pipeline import normalize, map_attack, correlate
    from .agents.budget import plan_before_after
    for p in args.paths:
        if not os.path.exists(p):
            print(f"[bluecell] path not found: {p}", file=sys.stderr)
            return 2
    from .agents import injection
    events = normalize(ingest_paths(args.paths, args.source))
    map_attack(events)
    injection.tag_events(events)      # as analyze() does: it can change incidents
    incidents = correlate(events, window_minutes=args.window)[:args.max_incidents]
    plan = plan_before_after(events, incidents, votes=args.votes, commander_limits={
        "max_agents": args.max_agents, "max_commander_turns": args.max_commander_turns,
        "budget_seconds": args.budget_seconds})
    print(json.dumps(plan, indent=2))
    return 0


def cmd_intel(args) -> int:
    store = IntelStore(args.intel_db) if args.intel_db else IntelStore()
    if args.intel_cmd == "stats":
        print(json.dumps(store.stats(), indent=2))
    elif args.intel_cmd == "add":
        if not args.id.strip():
            print("[bluecell] intel add: --id must not be empty", file=sys.stderr)
            return 2
        ok = store.add({
            "id": args.id, "title": args.title, "summary": args.summary or "",
            "severity": args.severity or "", "source": "manual",
            "keywords": (args.keywords or "").split(",") if args.keywords else [],
        })
        try:
            store.save()
        except (OSError, RuntimeError) as exc:
            print(f"[bluecell] intel add failed: {exc}", file=sys.stderr)
            return 2
        print("added" if ok else "already present (or missing id)")
    elif args.intel_cmd == "import":
        if not os.path.exists(args.file):
            print(f"[bluecell] file not found: {args.file}", file=sys.stderr)
            return 2
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"[bluecell] not a valid JSON feed: {args.file} ({exc})", file=sys.stderr)
            return 2
        records = data if isinstance(data, list) else (
            data.get("entries", data.get("vulnerabilities", [])) if isinstance(data, dict) else None)
        if not isinstance(records, list):
            print(f"[bluecell] expected a JSON list or an object with an \"entries\" / "
                  f"\"vulnerabilities\" list: {args.file}", file=sys.stderr)
            return 2
        # Non-object entries (e.g. bare numbers) would crash ingest; skip and report them.
        skipped = sum(1 for r in records if not isinstance(r, dict))
        if skipped:
            print(f"[bluecell] skipped {skipped} non-object record(s) in {args.file}", file=sys.stderr)
        try:
            n = store.ingest_cve_feed([r for r in records if isinstance(r, dict)])
        except (OSError, RuntimeError) as exc:
            print(f"[bluecell] intel import failed: {exc}", file=sys.stderr)
            return 2
        print(f"imported {n} new intel entries (total {len(store.entries)})")
    elif args.intel_cmd == "search":
        for e in store.search(args.terms.split(), limit=args.limit):
            print(f"{e.get('id')}: {e.get('title')} (sev {e.get('severity','?')})")
    else:
        print("unknown intel subcommand", file=sys.stderr)
        return 2
    return 0


def cmd_serve(args) -> int:
    for p in args.paths:
        if not os.path.exists(p):
            print(f"[bluecell] path not found: {p}", file=sys.stderr)
            return 2
    from .web import serve
    httpd = serve(args.paths, host=args.host, port=args.port, window=args.window,
          llm_mode=args.llm, model=args.model, intel_db=args.intel_db,
          open_browser=args.open, max_upload_mb=args.max_upload_mb,
          orchestration=args.orchestration, votes=args.votes,
          tier1_model=args.model_tier1)
    return 0 if httpd is not None else 2


def cmd_roster(args) -> int:
    # Build a static roster preview from the role classes.
    from .agents.roles import SPECIALISTS
    rows = [
        ("0", "soc-lead", "SOC Lead / Incident Commander (plans + deploys the "
                          "agents below; default with a model backbone, "
                          "--orchestration auto|commander)"),
        ("1", "soc1-<source>", "Tier-1 SOC Analyst (one per log source)"),
        ("2", "soc2-lead", "Tier-2 SOC Analyst (verification/confirmation)"),
    ]
    for cls in SPECIALISTS:
        rows.append(("3", cls().name, cls.role))
    print(provenance.banner())
    print("\nBlue-team agent swarm roster:")
    for tier, name, role in rows:
        print(f"  [T{tier}] {name:<28} {role}")
    return 0


def _print_ai(result) -> None:
    """Print the model-driven AI analyst conclusion, if it ran."""
    ai = result.get("ai_analysis")
    if not ai:
        return
    if not ai.get("available"):
        print(f"[bluecell] AI analyst: unavailable ({ai.get('reason', 'n/a')}); "
              f"deterministic verdict shown above.")
        return
    lead = ai.get("lead", {})
    seen = " (checked against the Tier-2 verdict)" if ai.get("tier2_verdicts_seen") else ""
    print(f"[bluecell] AI analyst (model-driven){seen}: {ai.get('final_verdict')} "
          f"(conf {lead.get('confidence')}): {lead.get('headline', '')}")


def cmd_info(args) -> int:
    info = {
        "version": __version__,
        "author": provenance.AUTHOR,
        "watermark": provenance.WATERMARK,
        "integrity": ("ok" if provenance.verify_integrity()[0] else "TAMPERED"),
        "python": sys.version.split()[0],
        "cli_backbone_available": LLMBackbone.available("cli"),
        "api_backbone_available": LLMBackbone.available("api"),
        "auto_backbone": None,
    }
    try:
        info["auto_backbone"] = LLMBackbone(mode="auto").resolved
    except BackboneUnavailable:
        info["auto_backbone"] = "none (deterministic mode)"
    try:
        info["intel"] = IntelStore().stats()
    except Exception as exc:  # pragma: no cover
        info["intel"] = f"error: {exc}"
    print(json.dumps(info, indent=2))
    return 0


def cmd_eval(args) -> int:
    from . import evals
    # check the --json target before the (slow) eval runs, as cmd_analyze does
    json_dir = os.path.dirname(os.path.abspath(args.json)) if args.json else ""
    if json_dir and not os.path.isdir(json_dir):
        print(f"[bluecell] cannot write eval JSON: directory not found: {json_dir}",
              file=sys.stderr)
        return 2
    backbone = _make_backbone(args.llm, args.model)
    if args.llm != "off" and backbone is None:
        print("[bluecell] eval: no backbone available; scoring the rules only.",
              file=sys.stderr)

    def progress(case):
        mark = "PASS" if case["passed"] else "FAIL"
        print(f"[bluecell] eval {case['name']}: {mark}", file=sys.stderr)
    try:
        report = evals.run_eval(args.cases, names=args.case or None, repeat=args.repeat,
                                llm=args.llm, backbone=backbone,
                                trace=(False if args.no_trace else None), progress=progress,
                                options={"votes": args.votes,
                                         "tier1_model": args.model_tier1,
                                         "orchestration": args.orchestration,
                                         "max_agents": args.max_agents,
                                         "max_commander_turns": args.max_commander_turns,
                                         "budget_seconds": args.budget_seconds})
    except FileNotFoundError as exc:
        print(f"[bluecell] {exc}", file=sys.stderr)
        return 2
    print(evals.format_report(report))
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, default=str)
        except OSError as exc:
            print(f"[bluecell] cannot write eval JSON: {exc}", file=sys.stderr)
            return 2
        print(f"[bluecell] wrote eval JSON -> {args.json}")
    return 0 if report["summary"]["cases_failed"] == 0 else 1


def _cost_text(s, dollar=False) -> str:
    cost = s.get("total_cost_usd")  # None = unknown; never shown as 0
    if cost is None:
        return "n/a"
    text = f"{'$' if dollar else ''}{cost:.4f}"
    return f">= {text}" if s.get("cost_unknown_calls") else text


def cmd_runs(args) -> int:
    from . import tracing
    if args.runs_cmd == "show":
        run = tracing.load_run(args.run_id)
        if run is None:
            print(f"[bluecell] run not found: {args.run_id} (in {tracing.runs_dir()})",
                  file=sys.stderr)
            return 2
        s = run["summary"]
        print(f"run {s.get('run_id')}  started {s.get('started')}  "
              f"verdict {s.get('verdict')}  backbone {s.get('backbone')}")
        print(f"inputs: {', '.join(s.get('inputs') or [])}")
        tok = s.get("tokens") or {}
        print(f"duration {s.get('duration_ms')} ms · LLM calls {s.get('llm_calls')} · "
              f"tool calls {s.get('tool_calls')} · tokens {tok.get('total', 0)} · "
              f"cost {_cost_text(s, dollar=True)} ({s.get('cost_note')})")
        print()
        for line in tracing.span_tree_lines(run):
            print(line)
        return 0
    runs = tracing.list_runs(limit=args.last)
    if not runs:
        print(f"[bluecell] no traced runs in {tracing.runs_dir()}")
        return 0
    rows = [("run id", "time (UTC)", "input", "verdict", "agents", "tools", "tokens",
             "cost $", "secs")]
    for s in runs:
        name = tracing.input_label(s.get("inputs"))
        rows.append((s.get("run_id"), (s.get("started") or "")[:19].replace("T", " "),
                     name[:40], s.get("verdict") or "-", s.get("agents", 0),
                     s.get("tool_calls", 0), (s.get("tokens") or {}).get("total", 0),
                     _cost_text(s) + ("~" if s.get("cost_estimated") and s.get("total_cost_usd") is not None else ""),
                     f"{(s.get('duration_ms') or 0) / 1000:.1f}"))
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    for i, r in enumerate(rows):
        print("  ".join(str(v).ljust(widths[j]) for j, v in enumerate(r)))
        if i == 0:
            print("  ".join("-" * w for w in widths))
    print("(~ = cost estimated from token counts at list prices)")
    return 0


ORCHESTRATIONS = ("auto", "commander", "fixed")
ORCH_HELP = ("How the agent swarm is organised: 'commander' = an LLM Incident "
             "Commander decides which agents to deploy; 'fixed' = Tier-1 -> Tier-2 "
             "-> Tier-3; 'auto' (default) = commander when a model backbone is "
             "available, fixed otherwise.")


def _add_commander_limits(p) -> None:
    from .agents.commander import (DEFAULT_MAX_AGENTS, DEFAULT_COMMANDER_TURNS,
                                   DEFAULT_BUDGET_SECONDS)
    p.add_argument("--max-agents", dest="max_agents", type=_positive_int,
                   default=DEFAULT_MAX_AGENTS,
                   help=f"Incident Commander: worker agents per run (default {DEFAULT_MAX_AGENTS})")
    p.add_argument("--max-commander-turns", dest="max_commander_turns", type=_positive_int,
                   default=DEFAULT_COMMANDER_TURNS,
                   help=f"Incident Commander: its own turn cap (default {DEFAULT_COMMANDER_TURNS})")
    p.add_argument("--budget-seconds", dest="budget_seconds", type=_budget_seconds,
                   default=DEFAULT_BUDGET_SECONDS,
                   help=f"Incident Commander: wall-clock budget (default {DEFAULT_BUDGET_SECONDS})")


def _add_swarm_args(p) -> None:
    """Orchestration flags shared by analyze and eval."""
    p.add_argument("--orchestration", choices=ORCHESTRATIONS, default="auto", help=ORCH_HELP)
    _add_commander_limits(p)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bluecell",
        description="BlueCell - Blue-Team Log Intelligence (read-only analysis).")
    p.add_argument("--version", action="version", version=f"bluecell {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze log files/dirs")
    a.add_argument("paths", nargs="+", help="Log files or directories")
    a.add_argument("--source", type=str.lower, choices=_SOURCE_CHOICES,
                   help="Override source type for all inputs "
                   f"({'|'.join(_SOURCE_CHOICES)})")
    a.add_argument("--window", type=_window, default=60,
                   help="Correlation window in minutes (default 60)")
    a.add_argument("--max-incidents", type=_positive_int, default=10, dest="max_incidents")
    a.add_argument("--no-agents", action="store_true", dest="no_agents",
                   help="Skip the agent swarm (pipeline only)")
    a.add_argument("--llm", choices=["auto", "cli", "api", "off"], default="auto",
                   help="LLM backbone mode (default auto; 'off' = deterministic)")
    a.add_argument("--model", default="claude-sonnet-5", help="Claude model")
    a.add_argument("--format", choices=["markdown", "json"], default="markdown")
    a.add_argument("--output", "-o", help="Write report to file instead of stdout")
    a.add_argument("--intel-db", dest="intel_db", help="Path to intel JSON store")
    a.add_argument("--model-tier1", dest="model_tier1", default=None,
                   help="Cheaper model for Tier-1 triage agents, e.g. claude-haiku-4-5 "
                        "(default: same as --model)")
    a.add_argument("--votes", type=_positive_int, default=1,
                   help="Run the Tier-2 verdict K times and majority-vote each incident "
                        "(default 1; 3 recommended for stable verdicts, ~K x Tier-2 cost)")
    a.add_argument("--all-tier1", action="store_true", dest="all_tier1",
                   help="Run a Tier-1 model agent for every source, even sources with "
                        "no events in any incident (default: rules cover those)")
    c = a.add_mutually_exclusive_group()
    c.add_argument("--no-cache", action="store_true", dest="no_cache",
                   help="Do not read or write the run cache")
    c.add_argument("--refresh", action="store_true",
                   help="Re-run even if cached, and overwrite the cached result")
    a.add_argument("--no-trace", action="store_true", dest="no_trace",
                   help="Do not save this run's trace under the runs dir")
    _add_swarm_args(a)
    a.set_defaults(func=cmd_analyze)

    ev = sub.add_parser("eval", help="Run the labelled eval suite")
    ev.add_argument("--cases", default="evals/cases", help="Cases directory (default evals/cases)")
    ev.add_argument("--case", action="append", help="Run only this case (repeatable)")
    ev.add_argument("--llm", choices=["auto", "cli", "api", "off"], default="off",
                    help="LLM backbone (default off = rules only)")
    ev.add_argument("--model", default="claude-sonnet-5", help="Claude model")
    ev.add_argument("--repeat", type=_positive_int, default=1,
                    help="Runs per case; reports verdict stability")
    ev.add_argument("--json", help="Write the full eval report as JSON")
    ev.add_argument("--no-trace", action="store_true", dest="no_trace",
                    help="Do not save run traces")
    ev.add_argument("--votes", type=_positive_int, default=1,
                    help="Tier-2 self-consistency runs per verdict (default 1)")
    ev.add_argument("--model-tier1", dest="model_tier1", default=None,
                    help="Cheaper model for Tier-1 triage agents (default: --model)")
    _add_swarm_args(ev)
    ev.set_defaults(func=cmd_eval)

    rn = sub.add_parser("runs", help="List traced runs, or show one run's span tree")
    rn.add_argument("--last", type=_positive_int, default=20, help="How many runs (default 20)")
    rns = rn.add_subparsers(dest="runs_cmd")
    rshow = rns.add_parser("show", help="Show one run's span tree")
    rshow.add_argument("run_id")
    rn.set_defaults(func=cmd_runs, runs_cmd=None)

    it = sub.add_parser("intel", help="Manage threat-intel knowledge base")
    it.add_argument("--intel-db", dest="intel_db", help="Path to intel JSON store")
    its = it.add_subparsers(dest="intel_cmd", required=True)
    its.add_parser("stats", help="Show intel store stats")
    ia = its.add_parser("add", help="Add one intel entry")
    ia.add_argument("--id", required=True)
    ia.add_argument("--title", required=True)
    ia.add_argument("--summary")
    ia.add_argument("--severity")
    ia.add_argument("--keywords", help="comma-separated")
    ii = its.add_parser("import", help="Import a CVE/intel JSON feed")
    ii.add_argument("file")
    isr = its.add_parser("search", help="Search intel")
    isr.add_argument("terms")
    isr.add_argument("--limit", type=_positive_int, default=10)
    it.set_defaults(func=cmd_intel)

    sv = sub.add_parser("serve", help="Launch the local web dashboard")
    sv.add_argument("paths", nargs="+", help="Log files or directories to analyze")
    sv.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    sv.add_argument("--port", type=_port, default=8787, help="Port 1-65535 (default 8787)")
    sv.add_argument("--window", type=_window, default=60, help="Correlation window minutes")
    sv.add_argument("--llm", choices=["auto", "cli", "api", "off"], default="off",
                    help="LLM backbone for RCA/agents (default off for speed)")
    sv.add_argument("--model", default="claude-sonnet-5")
    sv.add_argument("--intel-db", dest="intel_db", help="Path to intel JSON store")
    sv.add_argument("--open", action="store_true", help="Open the browser automatically")
    sv.add_argument("--max-upload-mb", dest="max_upload_mb", type=_positive_int, default=256,
                    help="Cap on each upload request body in MB (default 256), counted on "
                         "the whole JSON-encoded request, not the raw file size, so JSON "
                         "escaping counts against it. Staged uploads send one file per request.")
    sv.add_argument("--orchestration", choices=ORCHESTRATIONS,
                    default="auto", help=ORCH_HELP)
    sv.add_argument("--votes", type=_positive_int, default=1,
                    help="Tier-2 self-consistency runs per verdict (default 1)")
    sv.add_argument("--model-tier1", dest="model_tier1", default=None,
                    help="Cheaper model for Tier-1 triage agents (default: --model)")
    sv.set_defaults(func=cmd_serve)

    pl = sub.add_parser("plan", help="Offline cost plan for analyzing some logs")
    pl.add_argument("paths", nargs="+", help="Log files or directories")
    pl.add_argument("--source", type=str.lower, choices=_SOURCE_CHOICES,
                    help="Override source type for all inputs "
                    f"({'|'.join(_SOURCE_CHOICES)})")
    pl.add_argument("--window", type=_window, default=60)
    pl.add_argument("--max-incidents", type=_positive_int, default=10, dest="max_incidents")
    pl.add_argument("--votes", type=_positive_int, default=1)
    _add_commander_limits(pl)
    pl.set_defaults(func=cmd_plan)

    ro = sub.add_parser("roster", help="Show the blue-team agent swarm roster")
    ro.set_defaults(func=cmd_roster)

    inf = sub.add_parser("info", help="Show environment + backbone status")
    inf.set_defaults(func=cmd_info)

    return p


def _terminate(signum, frame):
    raise SystemExit(128 + signum)  # unwinds through the finally/close() that reap worker processes


def main(argv=None) -> int:
    # Authorship integrity gate: warns on stderr if attribution was removed/altered; never exits.
    provenance.enforce(strict=True)
    parser = build_parser()
    args = parser.parse_args(argv)
    prev = {}
    for name in ("SIGTERM", "SIGHUP"):      # default action would skip every finally
        try:
            prev[getattr(signal, name)] = signal.signal(getattr(signal, name), _terminate)
        except (AttributeError, ValueError):    # no SIGHUP / not the main thread
            pass
    try:
        return args.func(args)
    except (KeyboardInterrupt, SystemExit) as exc:
        code = 130 if isinstance(exc, KeyboardInterrupt) else exc.code
        # Only for a signal (Ctrl-C, or _terminate's 128+signum): a command's own SystemExit exits normally.
        interrupted = code in (130, 128 + signal.SIGTERM, 128 + getattr(signal, "SIGHUP", 1))
        if interrupted and any(t.name.startswith("ThreadPoolExecutor") for t in threading.enumerate()):
            # An in-flight model call can't be interrupted and the interpreter would join it at exit.
            # Callers' finally blocks already ran; run atexit (session close) then skip the join.
            sys.stdout.flush(); sys.stderr.flush()
            atexit._run_exitfuncs()
            os._exit(code if isinstance(code, int) else 1)
        raise
    finally:
        for sig, handler in prev.items():
            if handler is not None:
                signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
