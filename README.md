# BlueCell — Blue-Team Log Intelligence

> **Built by Harikishore Karunanithi** · Copyright (c) 2026 Harikishore Karunanithi · MIT (use and share freely, but keep the author attribution).
> <!-- WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi -->

BlueCell is a **read-only** multi-agent pipeline that turns raw security logs
into an investigation. Point it at logs from any source — EDR/endpoint, syslog,
DNS, firewall/router/switch, and cloud audit trails — and it will:

1. **Ingest** heterogeneous logs (JSON / JSONL / CSV / syslog).
2. **Normalize** everything to one compact, OCSF-inspired event schema.
3. **Compress** events into a token-lean digest (raw logs never hit the LLM).
4. **Map** activity to **MITRE ATT&CK** techniques (deterministic, explainable).
5. **Correlate** across sources on a timeline into scored **incidents**.
6. **Enrich** with always-current **threat intel** (RAG over a local CVE/TTP store).
7. **Reconstruct** the **RCA / attack storyline** (deterministic, optional LLM narrative).
8. **Emit IOCs** and a prioritized **threat-hunt checklist**.

> BlueCell is an analysis aid. It never touches your environment, sends nothing
> externally except optional NVD intel fetches and optional Claude API calls,
> and treats every finding as a hypothesis to validate — not proof.

## The agent swarm (true multi-agent model)

BlueCell runs a swarm of specialist blue-team agents, not a single script. Each
agent has a deterministic brain (always runs, offline) plus optional Claude
enrichment:

- **Tier 1 — Junior SOC Analysts:** one per log source, triage and raise candidates.
- **Tier 2 — Senior SOC Analysts:** verify/confirm or dismiss Tier-1 candidates
  (cross-source corroboration = confirmation).
- **Tier 3 — Specialists:** Incident Responder, Digital Forensics Analyst,
  Threat Hunter, Malware Analyst, Threat Intelligence Analyst,
  Security Engineer/Architect, Vulnerability Analyst.

An orchestrator fans work out across tiers and reconciles everything into a
per-incident **consensus** (which agents agreed, confirmation status, confidence).
See the roster any time: `bluecell roster`.

## Authorship & integrity

Built by **Harikishore Karunanithi**. Licensed MIT — you may use and share it,
but you must keep the author attribution. Every source file carries a watermark
header, and `provenance.py` runs an integrity check at startup: if the
attribution is removed or altered, BlueCell **halts** (exit 3) and prints where
the watermark lives so it can be restored. This detects casual rebranding; it is
not unbreakable DRM — the enforceable protection is the MIT license + copyright.

## Why it's different

- **Cross-source correlation into one storyline**, not per-tool alerts.
- **Token-efficient by design** — bursts collapse (`x500`), only distinct
  signatures reach the model, so log-scale analysis stays affordable.
- **Runs with zero dependencies and zero API key** — the entire core
  (parse → correlate → ATT&CK → IOC → deterministic RCA) is stdlib-only.
- **Always-current intel** via a local, auditable knowledge base you refresh on
  a schedule. The model isn't retrained; the *evidence* stays fresh (RAG).

## Install

```bash
cd bluecell
pip install -e .            # installs the `bluecell` command
# or run without installing:
export PYTHONPATH=src && python -m bluecell --help
```

Python 3.10+. No third-party packages required for the core.

## Quick start

```bash
# 1. Load threat intel (bundled sample, or your own CVE/TTP JSON)
bluecell intel import feeds/intel_feed.json

# 2. Analyze a folder of logs -> Markdown report
bluecell analyze samples --window 120 -o report.md

# 3. Launch the web dashboard (opens at http://127.0.0.1:8787)
bluecell serve samples --window 120 --open

# 4. See environment + which Claude backbone is available
bluecell info
```

## Web dashboard

```bash
bluecell serve samples --window 120 --port 8787 --open
# add --llm auto  to enable Claude-enriched RCA/agent notes
```

A dependency-free local dashboard (binds to `127.0.0.1`, read-only): a futuristic
"command deck" with a glassmorphism + neon theme and an animated particle
background.

**Drop your own logs right in the browser** — the top of the deck is a
drag-and-drop **log intake zone**. Drag log files (or click **Browse**), pick a
correlation window, and hit **Analyze**; the files are analyzed locally in a
throwaway temp dir and the deck updates. **Load Sample Attack** shows the bundled
demo. Nothing is sent to the internet.

The deck shows: animated hero metrics (**agents deployed**, **time to deduce**,
events, incidents), an **RCA Pinpointer** (radar crosshair locking onto
patient-zero / root cause / objective / blast radius), a **3D layered kill-chain
storyline you can drag to rotate**, the **agent-swarm constellation** (SOC core
with tier-ringed orbiting agents), incidents, IOC tables, a prioritized
threat-hunt checklist, and matched threat intel.

JSON/HTTP API: `GET /api/report`, `GET /api/refresh`, `GET /api/meta`,
`POST /api/upload` (`{files:[{name,content}], window}`, 40 MB cap).

Output is a full incident report: risk-scored incidents, RCA storyline, ATT&CK
phases, IOCs, and a prioritized hunt checklist. Use `--format json` for machine
output.

## The hybrid Claude backbone

The deterministic pipeline always runs. The **RCA narrative** is optionally
enriched by Claude, via one of two paths (auto-selected):

| Mode  | How | Best for |
|-------|-----|----------|
| `cli` | Shells out to your local `claude` CLI — **keyless** | Interactive local runs |
| `api` | Anthropic API via `ANTHROPIC_API_KEY` | Headless / scheduled runs |

```bash
bluecell analyze samples --llm auto      # prefer CLI, then API, then deterministic
bluecell analyze samples --llm off       # fully deterministic (no model)
bluecell analyze samples --llm api --model claude-sonnet-5
```

If no backbone is available, BlueCell prints a notice and produces a complete
deterministic storyline instead. It never fails for lack of a model.

## Keeping intel current (the "self-learning" layer)

```bash
# Pull recent CVEs from the public NVD API into the local intel store
python scripts/update_intel.py --days 3
python scripts/update_intel.py --days 7 --keyword ransomware
```

Schedule it (cron / launchd / your scheduler) so every analysis retrieves the
latest vulnerability and TTP context. Network failures are non-fatal.

## Supported inputs & sources

- **Formats:** `.json` (array or `{Records:[...]}`), `.jsonl`/`.ndjson`, `.csv`, `.log`/`.txt`/`.syslog`
- **Sources:** `edr`/`endpoint`, `dns`, `network`/`firewall`/`router`/`switch`, `cloud`/`cloudtrail`, `auth`, `syslog`
- Source type is auto-detected from a `source`/`log_type` field or the filename;
  override with `--source`.

## Layout

```
src/bluecell/
  models.py            Unified Event schema + timestamp parsing
  ingest/              Loaders + per-source parsers
  pipeline/            normalize, compress, attack (ATT&CK), correlate, ioc
  intel/               Local threat-intel store + RAG retrieval
  llm/                 Hybrid Claude backbone (cli | api)
  report/              RCA storyline + Markdown/JSON renderers
  analyzer.py          End-to-end orchestrator
  cli.py               Command-line interface
scripts/update_intel.py  Scheduled NVD CVE ingester
samples/                 Example multi-source attack chain
feeds/                   Example threat-intel feed
tests/                   Test suite (pytest)
```

## Testing

```bash
pip install pytest
pytest -q
```

## Scope & limitations (read this)

- **MVP scope:** Blue-team, read-only. Red/Purple/GRC are future phases planned
  on the same correlation core.
- The ATT&CK mapper is a curated **high-signal rule set**, not a full detection
  engine. Tune the rules in `pipeline/attack.py` to your environment.
- Correlation links events by shared entities within a time window; very noisy
  environments may need a tighter `--window` and custom entity handling.
- Findings are **hypotheses**. A human analyst validates before any action.

## License

MIT — see `LICENSE`.
