#!/usr/bin/env python3
# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Self-updating threat-intel ingester (the "always-current" layer).

Pulls recent CVEs from the public NVD 2.0 API (no API key required for modest
rates) and folds them into the BlueCell intel store. Run it on a schedule
(cron / launchd / the scheduled-tasks connector) so the analysis pipeline
always retrieves current vulnerability context via RAG.

This does NOT retrain any model — it keeps a local, auditable knowledge base
fresh. Network failures are non-fatal: the store is simply left unchanged.

Usage:
    python scripts/update_intel.py --days 3
    python scripts/update_intel.py --days 7 --keyword ransomware
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from bluecell.intel import IntelStore  # noqa: E402

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_nvd(days: int, keyword: str | None, limit: int) -> list:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": str(min(limit, 2000)),
    }
    if keyword:
        params["keywordSearch"] = keyword
    url = NVD_URL + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "bluecell-intel/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    records = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        descs = cve.get("descriptions", [])
        summary = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        # CVSS score if present (v3.1 preferred).
        sev = ""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                sev = str(metrics[key][0]["cvssData"].get("baseScore", ""))
                break
        records.append({
            "id": cid,
            "title": cid,
            "description": summary,
            "cvss": sev,
            "published": cve.get("published", ""),
            "source": "nvd",
        })
    return records


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Update BlueCell threat-intel store from NVD.")
    ap.add_argument("--days", type=int, default=3,
                    help="Look back this many days (NVD allows at most 120)")
    ap.add_argument("--keyword", help="Optional keyword filter (e.g. ransomware)")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--intel-db", dest="intel_db", help="Path to intel store JSON")
    args = ap.parse_args(argv)

    if not 1 <= args.days <= 120:
        ap.error("--days must be between 1 and 120 (the NVD API's maximum range)")
    store = IntelStore(args.intel_db) if args.intel_db else IntelStore()
    try:
        records = fetch_nvd(args.days, args.keyword, args.limit)
    except Exception as exc:  # network/parse errors are non-fatal
        print(f"[update_intel] fetch failed ({exc}); store left unchanged "
              f"({store.stats()['total']} entries).", file=sys.stderr)
        return 1
    added = store.ingest_cve_feed(records)
    print(f"[update_intel] fetched {len(records)} CVEs, added {added} new "
          f"(total {store.stats()['total']}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
