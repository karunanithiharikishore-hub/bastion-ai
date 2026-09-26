"""BlueCell command-line interface.

Commands:
  analyze   Run the full pipeline over log files/dirs and write a report.
  intel     Manage the threat-intel knowledge base (add / import / stats / search).
  info      Show environment + backbone availability.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .analyzer import analyze
from .intel import IntelStore
from .llm import LLMBackbone, BackboneUnavailable
from .report import render_markdown, render_json


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
    backbone = _make_backbone(args.llm, args.model)
    intel = IntelStore(args.intel_db) if args.intel_db else IntelStore()
    result = analyze(
        args.paths,
        source_override=args.source,
        window_minutes=args.window,
        max_incidents=args.max_incidents,
        backbone=backbone,
        intel_store=intel,
    )
    output = render_json(result) if args.format == "json" else render_markdown(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"[bluecell] wrote {args.format} report -> {args.output}")
        print(f"[bluecell] {len(result['incidents'])} incident(s), "
              f"{result['meta']['events_ingested']} events, "
              f"backbone={result['meta']['backbone']}")
    else:
        print(output)
    return 0


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
        with open(args.file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        records = data if isinstance(data, list) else data.get("entries", data.get("vulnerabilities", []))
        n = store.ingest_cve_feed(records)
        print(f"imported {n} new intel entries (total {len(store.entries)})")
    elif args.intel_cmd == "search":
        for e in store.search(args.terms.split(), limit=args.limit):
            print(f"{e.get('id')}: {e.get('title')} (sev {e.get('severity','?')})")
    else:
        print("unknown intel subcommand", file=sys.stderr)
        return 2
    return 0


def cmd_info(args) -> int:
    info = {
        "version": __version__,
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
        description="BlueCell — Blue-Team Log Intelligence (read-only analysis).")
    p.add_argument("--version", action="version", version=f"bluecell {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze log files/dirs")
    a.add_argument("paths", nargs="+", help="Log files or directories")
    a.add_argument("--source", help="Override source type for all inputs "
                   "(edr|dns|network|firewall|cloud|auth|syslog)")
    a.add_argument("--window", type=int, default=60,
                   help="Correlation window in minutes (default 60)")
    a.add_argument("--max-incidents", type=int, default=10, dest="max_incidents")
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

    inf = sub.add_parser("info", help="Show environment + backbone status")
    inf.set_defaults(func=cmd_info)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
