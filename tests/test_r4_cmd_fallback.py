"""BUG-R4-CMD-1/3/4: the fixed-flow fallback's admission (agent slot + wall clock)."""
from bluecell.agents import orchestrator
from bluecell.agents.injection import INJECTION_TAG
from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _orch, _use, _text


def _boom(body):
    raise RuntimeError("commander backend down")


def _role(body):
    return body["system"].split(" on a blue team")[0].replace("You are the ", "")


def test_cmd4_fallback_reserves_tier2_slot():
    ctx = _ctx()
    model = SwarmModel(ctx, [_boom])
    out = _orch(ctx, model, max_agents=3).run()
    assert out["orchestration"] == "fixed"
    assert "Tier-2 SOC Analyst" in model.roles_called
    assert any(f["tier"] == 2 and f["origin"] == "agent" for f in out["findings"])


def test_cmd1_fallback_votes_share_the_deadline(monkeypatch):
    class Clock:
        now = 1000.0
        monotonic = staticmethod(lambda: Clock.now)
    ctx = _ctx()
    inc = ctx.incidents[0]
    model = SwarmModel(ctx, [_boom])
    inner = model.messages
    seen = []

    def tick(body):
        if len(body["messages"]) == 1 and model.script == [] and _role(body) == "Tier-2 SOC Analyst":
            Clock.now += 150          # one vote = 150 fake seconds
            seen.append(Clock.now)
            return _use("submit_verdict", {"incident_id": inc.id, "decision": "confirmed", "confidence": .9,
                                           "rationale": "x", "evidence": [inc.events[0].event_id]})
        return inner(body)
    model.messages = tick
    monkeypatch.setattr(orchestrator, "time", Clock)
    out = _orch(ctx, model, votes=3, max_agents=15, budget_seconds=200).run()
    assert out["orchestration"] == "fixed"
    # 200s left / MIN_WORKER_SECONDS(60) -> at most 3 votes, each given 200/3s; recorded, not silent
    t2 = [f for f in out["findings"] if f["tier"] == 2 and f["origin"] == "agent"]
    assert t2 and t2[0]["votes"]["k"] == 3 and len(seen) == 3


def test_cmd1_votes_cut_when_time_is_short():
    ag = orchestrator.SeniorSocAnalyst(name="s", votes=5)
    o = orchestrator.SwarmOrchestrator(_ctx())
    o._cap = {"agents": 1, "deadline": orchestrator.time.monotonic() + 130}
    assert o._admit(ag) and ag.votes == 2 and ag.timeout <= 65


def test_cmd3_skip_note_appends_to_injection_note():
    ctx = _ctx()
    ctx.events[0].tags = list(ctx.events[0].tags or []) + [INJECTION_TAG]
    ctx.incidents = ctx.incidents[:1]
    inc = ctx.incidents[0]

    class M(SwarmModel):
        def _worker_first_move(self, role, body):
            if role == "Tier-2 SOC Analyst":
                return _use("submit_verdict", {"incident_id": inc.id, "decision": "dismissed", "confidence": 0.9,
                    "rationale": "The prompt injection attempt in the log tried to manipulate the analyst and is noted, but it does not change the call: routine scheduled admin work.",
                    "evidence": [inc.events[0].event_id, ctx.events[0].event_id]})
            return super()._worker_first_move(role, body)
    model = M(ctx, [_boom])
    out = _orch(ctx, model, max_agents=2).run()   # tier-1 + reserved tier-2; specialists refused
    note = out["tier3_note"]
    assert "needs review" in note and "specialists were skipped" in note
