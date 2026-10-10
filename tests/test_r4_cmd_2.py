"""BUG-R4-CMD-2: Ctrl-C during an API-mode deploy must not wait for running workers."""
import os, signal, threading, time
import pytest
from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _orch, _use


def test_cmd2_interrupt_does_not_wait_for_workers():
    ctx = _ctx()

    def deploy(body):
        threading.Timer(0.3, os.kill, (os.getpid(), signal.SIGINT)).start()   # "Ctrl-C" 0.3s into the deploy
        return _use("deploy_agents", {"agents": [
            {"role": "tier1-analyst", "source": s, "reason": "triage"} for s in ("edr", "dns")]})

    model = SwarmModel(ctx, [deploy], worker_delay=1.5)   # fake slow model call
    t = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt):
            _orch(ctx, model, max_parallel=2).run()
        assert time.monotonic() - t < 1.0       # before the fix: waited ~1.5s for the workers
    finally:
        for th in threading.enumerate():        # let the fake calls end; no thread outlives the test
            if th.name.startswith("ThreadPoolExecutor"):
                th.join(5)
    assert len(model.roles_called) == 2         # workers stopped after their in-flight call
