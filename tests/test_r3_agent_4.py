"""R3 AGENT-4: a Tier-1 agent whose source name is hashed in its agent name still
records the raw source in its run metadata (human-facing report only). The raw
source must not appear in the model-facing mission text."""
from conftest import SAMPLES
from bluecell.ingest import ingest_path
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.agents import AgentContext
from bluecell.agents.roles import JuniorSocAnalyst

RAW = "iam.amazonaws.com"


def _ctx():
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    return AgentContext(events=events, incidents=correlate(events, window_minutes=120),
                        iocs=extract_iocs(events), digest=compress(events), backbone=None)


def test_hashed_source_is_recorded_in_last_run_on_rules_path():
    ag = JuniorSocAnalyst(RAW)
    assert ag.name.startswith("soc1-src-")
    ag.run(_ctx(), use_llm=False)
    assert ag.last_run["source"] == RAW


def test_hashed_source_is_recorded_in_last_run_when_skipped():
    ag = JuniorSocAnalyst(RAW)
    ag.skip(_ctx(), "no incident events")
    assert ag.last_run["source"] == RAW


def test_plain_source_still_recorded_and_raw_source_not_in_mission():
    ag = JuniorSocAnalyst("edr")
    ag.skip(_ctx(), "x")
    assert ag.last_run["source"] == "edr"
    assert RAW not in JuniorSocAnalyst(RAW).brief()


def test_report_shows_raw_source_for_hashed_agent():
    from bluecell.report.render import _render_swarm
    md = _render_swarm({"agent_count": 1, "roster": [], "consensus": [], "findings": [],
                        "agent_runs": [{"agent": "soc1-src-1a2b3c4d", "tier": 1,
                                        "mode": "rules", "source": "Palo Alto"}]})
    assert "soc1-src-1a2b3c4d" in md and "source: Palo Alto" in md
