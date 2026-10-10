# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-R4-FEAT-4: shutdown (`_State.close`) must not wait for a running analysis, and
must still remove staged upload dirs. Offline: the analysis is a blocked stub."""
import os
import threading
import time

from bluecell.web.server import _State


def test_close_returns_promptly_while_analysis_runs(monkeypatch):
    state = _State([], 60, "off", "m", None)
    started, release = threading.Event(), threading.Event()

    def slow_analysis(paths, window, label=None):
        started.set()
        release.wait(30)
        return {}

    monkeypatch.setattr(state, "_analyze_paths", slow_analysis)
    staged = state.stage_reset()
    state.stage_add("a.log", "x\n", token=staged)
    kept = state.stage_reset()           # never run: must be removed by close()
    state.stage_add("b.log", "y\n", token=kept)
    run = threading.Thread(target=state.run_analysis, daemon=True)
    run.start()
    assert started.wait(5)               # analysis now holds the lock

    folders = [state.stages[staged][0], state.stages[kept][0]]
    closer = threading.Thread(target=state.close, daemon=True)
    t0 = time.time()
    closer.start()
    closer.join(2)
    try:
        assert not closer.is_alive(), "close() blocked on the analysis lock"
        assert time.time() - t0 < 2
        assert not any(os.path.exists(f) for f in folders)
    finally:
        release.set()
        run.join(5)
