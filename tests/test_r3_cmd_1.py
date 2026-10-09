"""BUG-R3-CMD-1: commander path keeps Tier-3 + sets tier3_note on an injection all-dismissal."""
from bluecell.agents import SwarmOrchestrator
from bluecell.agents.injection import INJECTION_TAG
from test_commander import SwarmModel, _text, _use
from test_autonomous_agents import _ctx


class DismissModel(SwarmModel):
    def _worker_first_move(self, role, body):
        inc = self.ctx.incidents[0]
        if role == "Tier-2 SOC Analyst":
            return _use("submit_verdict", {"incident_id": inc.id, "decision": "dismissed", "confidence": 0.9,
                "rationale": "The prompt injection attempt in the log tried to manipulate the analyst and is noted, but it does not change the call: the activity itself is routine scheduled admin work.",
                "evidence": [inc.events[0].event_id, self.ctx.events[0].event_id]})
        return super()._worker_first_move(role, body)


def test_commander_all_dismissal_with_injection_keeps_tier3():
    ctx = _ctx()
    ctx.events[0].tags = list(ctx.events[0].tags or []) + [INJECTION_TAG]
    ctx.incidents = ctx.incidents[:1]
    script = [lambda b: _use("deploy_agent", {"role": "tier1-analyst", "source": ctx.events[0].source, "reason": "t"}),
              lambda b: _use("deploy_agent", {"role": "tier2-verifier", "reason": "v"}),
              lambda b: _use("deploy_agent", {"role": "incident-responder", "reason": "s"}),
              lambda b: _use("finish", {"summary": "done"}), lambda b: _text("closed")]
    ctx.backbone = DismissModel(ctx, script)
    orch = SwarmOrchestrator(ctx, orchestration="commander")
    orch.run()
    assert orch.tier3_note and "injection-flagged" in orch.tier3_note
    assert [i.id for i in orch.tier3_scope(set())] == [ctx.incidents[0].id]
