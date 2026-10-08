# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BlueCell command-line interface.

Commands:
  analyze   Run the full pipeline + agent swarm and write a report.
  serve     Launch the local web dashboard.
  intel     Manage the threat-intel knowledge base (add / import / stats / search).
  roster    Show the blue-team agent swarm roster.
  info      Show environment + backbone availability + authorship.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, provenance
from .analyzer import analyze
from .intel import IntelStore
from .llm import LLMBackbone, BackboneUnavailable
from .report import render_markdown, render_json


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {value!r}")
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {n}")
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


def cmd_intel(args) -> int:
    store = IntelStore(args.intel_db) if args.intel_db else IntelStore()
    if args.intel_cmd == "stats":
        print(json.dumps(store.stats(), indent=2))
    elif args.intel_cmd == "add":
        ok = store.add({
            "id": args.id, "title": args.title, "summary": args.summary or "",
            "severity": args.severity or "", "source": "manual",
            "keywords": (args.keywords or "").split(",") if args.keywords else [],
        })
        store.save()
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
        n = store.ingest_cve_feed(records)
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
          open_browser=args.open, max_upload_mb=args.max_upload_mb)
    return 0 if httpd is not None else 2


def cmd_roster(args) -> int:
    # Build a static roster preview from the role classes.
    from .agents.roles import SPECIALISTS
    rows = [
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bluecell",
        description="BlueCell - Blue-Team Log Intelligence (read-only analysis).")
    p.add_argument("--version", action="version", version=f"bluecell {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze log files/dirs")
    a.add_argument("paths", nargs="+", help="Log files or directories")
    a.add_argument("--source", help="Override source type for all inputs "
                   "(edr|dns|network|firewall|cloud|auth|syslog)")
    a.add_argument("--window", type=_positive_int, default=60,
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
    a.set_defaults(func=cmd_analyze)

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
    isr.add_argument("--limit", type=int, default=10)
    it.set_defaults(func=cmd_intel)

    sv = sub.add_parser("serve", help="Launch the local web dashboard")
    sv.add_argument("paths", nargs="+", help="Log files or directories to analyze")
    sv.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    sv.add_argument("--port", type=int, default=8787, help="Port (default 8787)")
    sv.add_argument("--window", type=_positive_int, default=60, help="Correlation window minutes")
    sv.add_argument("--llm", choices=["auto", "cli", "api", "off"], default="off",
                    help="LLM backbone for RCA/agents (default off for speed)")
    sv.add_argument("--model", default="claude-sonnet-5")
    sv.add_argument("--intel-db", dest="intel_db", help="Path to intel JSON store")
    sv.add_argument("--open", action="store_true", help="Open the browser automatically")
    sv.add_argument("--max-upload-mb", dest="max_upload_mb", type=int, default=256,
                    help="Upload request-body cap in MB (default 256). The dashboard "
                         "sends one file per request, JSON-encoded, so this is roughly "
                         "the largest single file; total batch size is limited only by disk.")
    sv.set_defaults(func=cmd_serve)

    ro = sub.add_parser("roster", help="Show the blue-team agent swarm roster")
    ro.set_defaults(func=cmd_roster)

    inf = sub.add_parser("info", help="Show environment + backbone status")
    inf.set_defaults(func=cmd_info)

    return p


def main(argv=None) -> int:
    # Authorship integrity gate: halts if attribution was removed/altered.
    provenance.enforce(strict=True)
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
