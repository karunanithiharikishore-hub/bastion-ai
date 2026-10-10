"""BUG-FEAT-1: agent threads of two concurrent runs must each record their LLM
usage in their own run's trace. No real model calls: fake agents only."""
import threading

from bastion import tracing
from bastion.agents.orchestrator import SwarmOrchestrator

N_AGENTS = 6


class _FakeAgent:
    tier = 1
    role = "fake"
    last_run = {"mode": "autonomous"}

    def __init__(self, i):
        self.name = f"fake-{i}"

    def run(self, ctx, use_llm=True, session=None):
        # Usage is recorded from the pool thread; the sleep lets both runs overlap.
        tracing.record_llm({"input_tokens": 10, "output_tokens": 1},
                           model="claude-sonnet-5", source="api")
        threading.Event().wait(0.01)
        return []


def test_concurrent_runs_each_keep_their_own_llm_usage():
    barrier = threading.Barrier(2)
    summaries = {}

    def analysis(name):
        t = tracing.start_run([name], persist=False)
        try:
            barrier.wait()   # both runs are live before any agent starts
            orch = SwarmOrchestrator(ctx=None, use_llm=True, max_parallel=4)
            orch._run_all([_FakeAgent(i) for i in range(N_AGENTS)], None, session=object())
        finally:
            summaries[name] = tracing.end_run(t)

    threads = [threading.Thread(target=analysis, args=(n,)) for n in ("A", "B")]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    for name in ("A", "B"):
        assert summaries[name]["llm_calls"] == N_AGENTS, summaries[name]
