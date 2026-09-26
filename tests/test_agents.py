# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
import json
import os

from conftest import SAMPLES, FEEDS
from bluecell.ingest import ingest_path
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.intel import IntelStore
from bluecell.agents import run_swarm, SwarmOrchestrator, AgentContext
from bluecell.agents.roles import (
    JuniorSocAnalyst, SeniorSocAnalyst, IncidentResponder, SPECIALISTS,
)


def _ctx(tmp_path):
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    incidents = correlate(events, window_minutes=120)
    iocs = extract_iocs(events)
    digest = compress(events)
    store = IntelStore(str(tmp_path / "intel.json"))
    with open(os.path.join(FEEDS, "intel_feed.json")) as fh:
        store.ingest_cve_feed(json.load(fh))
    return AgentContext(events=events, incidents=incidents, iocs=iocs,
                        digest=digest, intel_store=store, backbone=None)


def test_swarm_spawns_expected_agents(tmp_path):
    ctx = _ctx(tmp_path)
    out = SwarmOrchestrator(ctx, use_llm=False).run()
    # Tier-1 per source + one Tier-2 lead + 7 specialists.
    roles = {a["role"] for a in out["roster"]}
    assert "Tier-1 SOC Analyst" in roles
    assert "Tier-2 SOC Analyst" in roles
    assert "Incident Responder" in roles
    assert "Digital Forensics Analyst" in roles
    assert "Threat Hunter" in roles
    assert "Malware Analyst" in roles
    assert "Threat Intelligence Analyst" in roles
    assert "Security Engineer / Architect" in roles
    assert "Vulnerability Analyst" in roles
    assert out["agent_count"] >= 10


def test_tier1_raises_then_tier2_confirms(tmp_path):
    ctx = _ctx(tmp_path)
    out = SwarmOrchestrator(ctx, use_llm=False).run()
    assert out["counts"]["tier1_findings"] >= 1
    assert out["counts"]["confirmed_incidents"] >= 1
    # The top incident should be confirmed by Tier-2 with multiple agents.
    top = out["consensus"][0]
    assert top["confirmed_by_tier2"] is True
    assert top["agents_involved"] >= 3
    assert 3 in top["tiers_involved"]     # specialists engaged


def test_tier2_dismisses_uncorroborated_singleton():
    from bluecell.models import Event
    # One lonely low-severity event, single source, no ATT&CK -> not confirmed.
    e = Event(ts="2026-09-26T09:00:00Z", source="syslog", category="other",
              action="log", message="benign", host="h1")
    e.attack.append("T1059")   # force it into an incident so tier1 sees it
    incidents = correlate([e], window_minutes=30)
    ctx = AgentContext(events=[e], incidents=incidents,
                       iocs=extract_iocs([e]), digest=compress([e]))
    out = SwarmOrchestrator(ctx, use_llm=False).run()
    # Single source, score < 50 -> Tier-2 should not confirm.
    assert out["counts"]["confirmed_incidents"] == 0


def test_specialist_incident_responder_containment(tmp_path):
    ctx = _ctx(tmp_path)
    ir = IncidentResponder()
    findings = ir.analyze(ctx)
    assert findings
    assert any("Isolate" in (f.recommended_action or "") for f in findings)


def test_run_swarm_helper_deterministic(tmp_path):
    ctx = _ctx(tmp_path)
    out = run_swarm(ctx.events, ctx.incidents, ctx.iocs, ctx.digest,
                    intel_store=ctx.intel_store, backbone=None, use_llm=False)
    assert out["findings"]
    # Every finding serializes cleanly.
    json.dumps(out)
