<div align="center">

# Bastion AI

**Your AI fortress of security analysts.**

Drop in your security logs. A team of AI SOC agents investigates them and hands back a verdict, the attack storyline, IOCs and an IR report — every claim checked against your actual log lines.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Runs locally](https://img.shields.io/badge/runs-locally%2C%20read--only-informational) ![Powered by Claude](https://img.shields.io/badge/powered%20by-Claude%20Code-8A63D2)

![Agent SOC floor](docs/screenshots/05-swarm.png)

</div>

## Why

Startups and small teams collect plenty of logs but have no blue team to read them. The evidence of one attack is split across Entra, EDR, DNS and the firewall, and nobody has time to stitch it together. Bastion AI does that stitching and puts a team of AI analysts on it, using the Claude Code you already run on your Mac.

## Highlights

- **No API key on a Mac with Claude Code** — every agent runs as its own `claude -p` session on your existing login.
- **Local and read-only** — logs stay on your machine; Bastion never touches your environment.
- **Many sources, one storyline** — events from every source go on one timeline, mapped to MITRE ATT&CK and correlated into scored incidents.
- **A real SOC team** — Incident Commander, one Tier-1 analyst per log source, a Tier-2 verifier, and 7 specialists (IR, forensics, threat hunting, malware, threat intel, security architecture, vulnerabilities).
- **Grounded, not hallucinated** — findings must cite real event IDs; any IP, domain or hash not in your logs is rejected.
- **Prompt-injection aware** — logs are treated as hostile data; planted instructions are flagged, never obeyed.
- **Two speeds** — *Quick analysis* (~1 min) or *Deep investigation* with the full agent swarm.
- **Live dashboard** — drag and drop logs and watch the agents deploy, call tools and file findings in real time.

## Quick start (macOS + Claude Code)

```bash
git clone https://github.com/karunanithiharikishore-hub/bastion-ai.git
cd bastion-ai
pip3 install -e .
bastion serve samples --llm cli --open
```

Drop your own logs onto the page and press **QUICK ANALYSIS** or **DEEP INVESTIGATION**.
Needs Python 3.10+ and the `claude` CLI logged in (`bastion info` shows what it found). No model? `--llm off` runs the full rules pipeline with zero dependencies.

**CLI report instead of the dashboard:**

```bash
bastion analyze ./logs --mode quick -o report.md
```

## Supported logs

| Category | Formats |
|---|---|
| Endpoint | EDR JSON/JSONL, Windows Security (CSV, XML) |
| Identity | Microsoft Entra sign-ins (interactive and non-interactive), Microsoft 365 Unified Audit Log |
| Network | Firewall (Cisco ASA, CEF, LEEF, CSV), DNS, syslog |
| Cloud | AWS CloudTrail |

## How it works

```
logs ─► ingest & normalize ─► ATT&CK mapping ─► cross-source correlation ─► incidents
                                                                              │
          report ◄── grounding check ◄── Incident Commander + agent swarm ◄───┘
```

1. **Ingest** any mix of sources into one compact event schema; raw logs never go to the model.
2. **Map and correlate** — deterministic ATT&CK rules, then events sharing a host, user or IP are linked into scored incidents.
3. **Investigate** — the Incident Commander deploys agents with read-only tools (`search_events`, `pivot`, `get_incident`, …). They share leads on a common board.
4. **Verify** — Tier-2 confirms or dismisses each incident; every finding is fact-checked against the logs before it is accepted.

| Mode | What runs | Time |
|---|---|---|
| Quick | Rules pipeline + one AI analyst (lead + reviewer) | ~1 min |
| Deep | Incident Commander + full agent swarm | several minutes |

## Screenshots

| Dashboard | Verdict |
|---|---|
| ![Dashboard](docs/screenshots/01-intake.png) | ![Verdict](docs/screenshots/02-verdict.png) |
| **Attack summary** | **Kill-chain storyline** |
| ![Summary](docs/screenshots/03-summary.png) | ![Storyline](docs/screenshots/04-storyline.png) |

## Scope

- An analysis aid, not a replacement for professional incident response. Findings are hypotheses for a human to validate.
- Analyses logs you provide; it is not 24/7 monitoring.
- The distilled evidence brief is sent to Claude, so it is not air-gapped.

**Roadmap:** read-only connectors that pull Entra/O365, Linux auth, endpoint, CloudTrail, CloudWatch and Azure logs directly from their APIs, indexed so agents can search history.

## Docs

Everything else — agent tiers and guardrails, injection defenses, repeatability and cost, tracing, evals, the HTTP API, CLI flags and testing — is in **[docs/REFERENCE.md](docs/REFERENCE.md)**.

## License

MIT © 2026 Harikishore Karunanithi. Please keep the author attribution.
