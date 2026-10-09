"""BUG-CMD-1: the API agent loop must honour the agent's wall-clock timeout.
No real model calls: a fake backbone that sleeps."""
import time

from bluecell.agents import AgentContext
from bluecell.agents.roles import ThreatHunter
from bluecell.agents.runtime import SwarmSession

from test_autonomous_agents import _ctx
from test_commander import _use


class SlowBackbone:
    resolved = "api"
    model = "fake"

    def __init__(self, delay=0.5):
        self.delay = delay
        self.calls = 0

    def messages(self, body):          # no timeout parameter: loop-level check only
        self.calls += 1
        time.sleep(self.delay)
        return _use("case_overview", {}, uid=f"u{self.calls}")


class TimeoutAwareBackbone(SlowBackbone):
    def __init__(self):
        super().__init__(delay=0.0)
        self.seen_timeouts = []

    def messages(self, body, timeout=None):
        self.seen_timeouts.append(timeout)
        return _use("case_overview", {}, uid="u")


def _run(backbone, timeout):
    ctx = _ctx()
    ctx.backbone = backbone
    agent = ThreatHunter()
    agent.timeout = timeout
    agent.max_turns = 50
    session = SwarmSession(ctx, seed=[])
    try:
        t0 = time.monotonic()
        agent.run(ctx, session=session)
        return time.monotonic() - t0, agent.last_run
    finally:
        session.close()


def test_api_loop_stops_at_timeout_with_recorded_error():
    backbone = SlowBackbone(delay=0.5)
    elapsed, run = _run(backbone, timeout=1)
    # Stops once the budget is spent: one call past the deadline at most.
    assert elapsed < 2.5, elapsed
    assert backbone.calls <= 3
    assert run["error"] and run["error"].startswith("timed out"), run["error"]
    assert run["truncated"] is True


def test_api_request_gets_only_the_time_left():
    backbone = TimeoutAwareBackbone()
    _run(backbone, timeout=30)
    assert backbone.seen_timeouts, "backbone was never called"
    assert all(0 < t <= 30 for t in backbone.seen_timeouts), backbone.seen_timeouts
    assert backbone.seen_timeouts == sorted(backbone.seen_timeouts, reverse=True)
