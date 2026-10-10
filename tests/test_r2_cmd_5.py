# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""BUG-CMD-5: a second verifier that files no agent verdict must not change
Tier-1 statuses. Its rule verdict is discarded by merge_tier2 (the first
verifier's agent verdict stands), so Tier-1 and Tier-2 must still agree."""
from test_commander import SwarmModel, _orch, _use, _text
from test_autonomous_agents import _ctx


class _VerifierNoVerdictSecond(SwarmModel):
    n2 = 0

    def _worker_first_move(self, role, body):
        if role == "Tier-2 SOC Analyst":
            type(self).n2 += 1
            if type(self).n2 == 2:
                return _text("no verdict, sorry")
            inc = self.ctx.incidents[0]
            return _use("submit_verdict", {
                "incident_id": inc.id, "decision": "dismissed", "confidence": 0.9,
                "rationale": "benign admin activity", "evidence": [inc.events[0].event_id]})
        return super()._worker_first_move(role, body)


def test_rule_verdict_of_discarded_second_verifier_leaves_tier1_alone():
    _VerifierNoVerdictSecond.n2 = 0
    ctx = _ctx()
    inc = ctx.incidents[0]
    script = [lambda b: _use("deploy_agent", {"role": "tier1-analyst", "source": "edr", "reason": "t"}),
              lambda b: _use("deploy_agent", {"role": "tier2-verifier", "reason": "v1"}),
              lambda b: _use("deploy_agent", {"role": "tier2-verifier", "reason": "v2"}),
              lambda b: _use("finish", {"summary": "s"}), lambda b: _text("ok")]
    orch = _orch(ctx, _VerifierNoVerdictSecond(ctx, script))
    res = orch.run()
    assert res["orchestration"] == "commander"

    tier2 = [f for f in res["findings"] if f["tier"] == 2 and f["incident_id"] == inc.id]
    tier1 = [f for f in res["findings"] if f["tier"] == 1 and f["incident_id"] == inc.id]
    assert [f["origin"] for f in tier2] == ["agent"] and tier2[0]["status"] == "dismissed"
    assert tier1 and all(f["status"] == "dismissed" for f in tier1)
    assert res["counts"]["confirmed_incidents"] == 0
