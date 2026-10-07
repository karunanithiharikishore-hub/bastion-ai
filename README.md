# BlueCell — Blue-Team Log Intelligence

> Built by **Harikishore Karunanithi** · Copyright (c) 2026 · MIT.

**What it is:** a local, read-only pipeline that lets you point an LLM (Claude)
at **gigabytes of messy, multi-source security logs** and get back a **grounded,
repeatable** incident analysis — verdict, attack storyline, IOCs, and an IR
report. The model does the reasoning; BlueCell does the part a chat window can't:
ingest at scale, normalize, correlate, **distill to what matters, and
fact-check the model's output against the logs so it can't invent indicators.**

**What it is *not*:** it is not "smarter than Claude" — it *is* Claude under the
hood. For a handful of logs that fit in a chat, pasting them into Claude directly
is simpler and often just as good. BlueCell earns its place when the logs are
**too big or too many to paste**, or when you need **repeatable, automated,
locally-run** analysis with grounding guarantees. See
[Honest positioning](#honest-positioning-when-to-use-this) below.

## Pipeline

Point it at logs from any source — EDR/endpoint, syslog, DNS,
firewall/router/switch, cloud audit trails, and **Microsoft 365 / Entra**
(sign-in logs + Unified Audit Log) — and it will:

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

## The agent swarm

BlueCell runs three tiers of blue-team agents. **Every one of them is an
autonomous, tool-using Claude agent** when a model backbone is available:

- **Tier 1 — Junior SOC Analysts:** one per log source, run in parallel. Each
  triages its own source and raises candidates. A candidate must cite at least
  one event from that analyst's source.
- **Tier 2 — Senior SOC Analyst:** does not take Tier-1 on trust. It
  re-examines the evidence, looks for benign explanations and for anything
  Tier-1 missed, and records a `confirmed` / `dismissed` verdict per incident
  with `submit_verdict` (a tool only Tier-2 has). Confirmed incidents go to
  Tier 3.
- **Tier 3 — Specialists:** Incident Responder, Digital Forensics Analyst,
  Threat Hunter, Malware Analyst, Threat Intelligence Analyst, Security
  Engineer/Architect, Vulnerability Analyst, run in parallel on the confirmed
  incidents.

All tiers share one board, so later tiers read the notes earlier tiers left.

Each agent gets a mission brief for its role and a
toolbox (`case_overview`, `search_events`, `get_incident`, `get_event`, `pivot`,
`aggregate`, `list_iocs`, `attack_lookup`, `intel_search`, `read_board`,
`post_note`, `submit_finding`) and runs its own loop: the model decides what to
look at, follows leads across all the logs, shares leads with the other
agents on the shared board, and files findings.

Findings are **checked against the evidence before they are accepted**:
evidence must be real event ids, ATT&CK techniques must be tagged on the cited
events, and any IP/domain/hash in the text must occur in the logs. A rejected
finding goes back to the agent with the reasons, and the agent fixes and
resubmits it.

How it runs depends on the backbone:

- `--llm cli` (keyless): each agent is its own `claude -p` process with
  BlueCell's tools served over MCP (`agents/mcp_server.py`) and every built-in
  Claude Code tool disabled, so the agent can only read the evidence.
- `--llm api`: native Anthropic tool use, looped in-process.
- `--llm off` / no backbone: every agent falls back to its rule-based logic
  (per-source triage rules, the cross-source corroboration rule for Tier-2,
  and fixed playbooks for the specialists).

The report's **"How each agent ran"** section shows, for every agent,
whether it ran autonomously or fell back to rules (and why), how many tool calls
it made, and how many submissions were rejected by grounding. Every finding and
verdict is labelled `AI agent` or `rule`. On the bundled samples a full
autonomous run takes roughly 10-15 minutes (three rounds of agents); `--llm off`
takes well under a second.

The orchestrator reconciles all tiers into a per-incident **consensus**. See the
roster any time: `bluecell roster`.

## Authorship & integrity

Built by **Harikishore Karunanithi**. Licensed MIT — you may use and share it,
but you must keep the author attribution. Every source file carries a watermark
header, and `provenance.py` runs an integrity check at startup: if the
attribution is removed or altered, BlueCell prints a warning asking for the
credit to be kept. It never stops the program: the enforceable protection is
the MIT license + copyright, not a runtime kill switch.

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
# add --llm auto  to run every swarm agent as an autonomous Claude agent
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

The deterministic pipeline (parse, normalize, correlate, ATT&CK tagging, IOCs)
always runs. Claude powers the **agent swarm** (every tier), the **AI analyst**
lead/reviewer verdict, and the **RCA narrative**, via one of two paths
(auto-selected):

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
samples_benign/          Benign maintenance window that trips the rules (false-positive test)
feeds/                   Example threat-intel feed
tests/                   Test suite (pytest)
```

## Testing

```bash
pip install pytest
pytest -q
```

## Honest positioning (when to use this)

I built this to learn, and I'd rather be straight about where it helps:

| Situation | Better choice |
|---|---|
| A few logs that fit in a chat, one-off, human-led | **Just paste them into Claude.** BlueCell is overhead. |
| 40 MB across dozens of files, hundreds of thousands of rows | **BlueCell** — you can't paste that; it distills + grounds it. |
| You need repeatable, automated, comparable output across many cases | **BlueCell** |
| You need a grounded answer that can't invent IOCs | **BlueCell** (grounding check) |
| **A startup/SMB with no SOC or blue team** | **BlueCell** — a local first-pass triage + IR report to know *fast* whether to escalate to a DFIR firm. |
| Maximum depth on a single incident | A skilled analyst reading raw logs (or Claude on the raw files) |

### For teams with no security function

Most early-stage companies can't tell whether a strange Microsoft 365 sign-in was
an attack, and can't afford a SOC. BlueCell lets one engineer or an MSP export
Entra / M365 logs, run it locally, and get a grounded verdict plus a shareable IR
report. It is **triage and escalation support, not a replacement for professional
incident response** — when it flags "likely malicious," you hand the report to a
DFIR firm and find out in minutes, not weeks.

The value here is the **engineering around the model** — ingestion, normalization,
correlation, distillation, grounding, and repeatable reporting — not the
reasoning itself. Its main current weakness is that the evidence brief is
**lossy** (it summarizes), so a person on the raw logs can still see more.

## Scope & limitations (read this)

- **Deterministic mode vs AI mode.** With `--llm off` (default), the verdict/RCA
  come from **rule-based Python** — fast and offline, but shallow: it will miss
  attack patterns it has no rule for. With `--llm auto`, model-driven agents
  (Lead DFIR + Tier-2 reviewer) reason over the evidence and are far stronger,
  but slower (real model calls) and require the `claude` CLI or an API key.
- **Grounding, not magic.** LLM output is fact-checked against the ingested
  events; any indicator not in the logs is flagged UNVERIFIED. This reduces —
  does not eliminate — error. Findings are **hypotheses**; a human validates.
- The ATT&CK mapper is a curated **high-signal rule set**, not a full detection
  engine. Coverage is best for identity / Microsoft 365 attacks and common
  endpoint/network patterns.
- Red / Purple / GRC are **not built** — this is Blue-team, read-only.
- It sends the distilled brief to the model, so it is **not air-gapped**.

## Project evolution (the honest version)

v1 was fully deterministic and, on a real Microsoft 365 compromise, **called it
"benign noise" — a false negative on a genuine breach.** Fixing that is what
taught the real lessons in this repo: (1) the agents had to actually *reason*
over evidence with a model instead of running fixed rules; (2) the parser had to
surface the signal that mattered (device-code flow, Unified Audit Log
operations, inbox rules, mailbox access); and (3) the model's output had to be
**grounded** so it couldn't hallucinate IOCs. The commit history shows that arc.

## License

MIT — see `LICENSE`. Please keep the author attribution.
