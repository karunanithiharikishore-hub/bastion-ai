"""BUG-INJ-10 follow-up: an all-dismissed case that holds injection-flagged events
must still reach Tier-3 (the injection attempt is itself an indicator)."""
from test_injection import _attack_ctx
from bastion.agents.orchestrator import SwarmOrchestrator
from bastion.agents.injection import is_flagged


class DismissAllWithDenial:
    """Tier-1 looks, Tier-2 dismisses every incident with a rationale that the
    verdict guard accepts (it explains the injected text), then specialists run."""
    resolved = "api"
    model = "fake"

    def __init__(self, incidents):
        self.incidents = incidents
        self.roles_called = set()

    def messages(self, body):
        role = body["system"].split(" on a blue team")[0].replace("You are the ", "")
        self.roles_called.add(role)
        n = len(body["messages"])
        if role == "Tier-2 SOC Analyst" and n == 1:
            return {"content": [
                {"type": "tool_use", "id": f"v{i}", "name": "submit_verdict",
                 "input": {"incident_id": inc.id, "decision": "dismissed",
                           "confidence": 0.8,
                           "rationale": "The injected log text is an attempt to steer the "
                                        "analyst and does not change the verdict; known scan.",
                           "evidence": [e.event_id for e in inc.events
                                        if is_flagged(e)][:1]}}
                for i, inc in enumerate(self.incidents)]}
        if n == 1:
            return {"content": [{"type": "tool_use", "id": "o",
                                 "name": "case_overview", "input": {}}]}
        return {"content": [{"type": "text", "text": "done"}]}


def test_all_dismissed_injection_case_still_runs_tier3(tmp_path):
    ctx = _attack_ctx(tmp_path)
    model = DismissAllWithDenial(ctx.incidents)
    ctx.backbone = model
    out = SwarmOrchestrator(ctx).run()
    assert out["tier3_skipped"] is None
    assert 3 in {r["tier"] for r in out["agent_runs"]}
    assert model.roles_called - {"Tier-1 SOC Analyst", "Tier-2 SOC Analyst"}
    assert "injection-flagged" in out["tier3_note"] and "needs review" in out["tier3_note"]


def test_all_dismissed_clean_case_still_skips_tier3(tmp_path):
    from test_autonomous_agents import _ctx, DismissAll
    ctx = _ctx()
    assert not any("injection:suspected" in e.tags for e in ctx.events)
    ctx.backbone = DismissAll(ctx.incidents)
    out = SwarmOrchestrator(ctx).run()
    assert out["tier3_skipped"] and out["tier3_note"] is None
