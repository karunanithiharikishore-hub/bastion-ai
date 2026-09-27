# GitHub listing — copy/paste

## Repo name
`bluecell`

## About (short description — GitHub "About" field)
> Local, grounded AI pipeline that turns gigabytes of messy multi-source security
> logs (EDR, syslog, DNS, firewall, Microsoft 365 / Entra) into a repeatable
> incident analysis — verdict, ATT&CK storyline, IOCs, and an IR report. The LLM
> reasons; BlueCell ingests at scale and fact-checks the output so it can't invent IOCs.

## Website field
(leave blank, or link your LinkedIn writeup / blog)

## Topics (tags)
```
dfir  incident-response  soc  blue-team  detection-engineering
mitre-attack  threat-hunting  microsoft-365  entra-id  azure-ad
unified-audit-log  llm  ai-security  llm-grounding  siem
security-tools  python  log-analysis  bec  ir-report
```

## One-line tagline (for social preview / pinned)
> Point an LLM at 40 MB of raw logs and get a grounded, repeatable incident report.

## Pinned "why this exists" blurb (optional, for profile README or post)
> BlueCell started as a test: how close can an AI system get to a human analyst's
> RCA of a real Microsoft 365 compromise? My first version confidently called a
> genuine breach "benign." Fixing that — making the agents actually reason,
> surfacing the right evidence (device-code flow, Unified Audit Log ops, inbox
> rules), and grounding the model so it can't hallucinate IOCs — is what this repo
> is really about. The commit history shows the whole arc.

## Suggested first Release (v0.13.0) notes
**BlueCell v0.13.0 — first public release**

A local, read-only pipeline that lets an LLM investigate large multi-source log
sets with grounding and repeatability.

Highlights
- Ingests EDR / syslog / DNS / firewall / cloud + **Microsoft 365 Entra sign-ins
  and Unified Audit Log**; normalizes to a compact schema.
- **Model-driven DFIR agents** (Lead + Tier-2 reviewer) reason over a distilled
  evidence brief (`--llm auto`); deterministic rule mode runs offline (`--llm off`).
- **Grounding**: every IP / domain / hash / technique the model cites is
  verified against the logs; invented indicators are flagged UNVERIFIED.
- MITRE ATT&CK mapping, IOC extraction, prioritized threat-hunt checklist.
- **Analyst verdict** (real / benign / needs-review) with reasoning and next steps.
- Futuristic local **web dashboard** (drag-and-drop logs, RCA pinpointer, 3D
  kill-chain, agent swarm view) + downloadable Markdown **IR report**.
- Honest limitations documented; validated against an independent forensic RCA.

76 tests. MIT. Built by Harikishore Karunanithi.
