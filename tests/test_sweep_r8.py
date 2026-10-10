"""ITEM-8 regression: the worker kill is portable. On Windows there is no os.killpg
and no signal.SIGKILL; the kill must fall back to `taskkill /T` and the Popen must
use CREATE_NEW_PROCESS_GROUP. Simulated here on POSIX by deleting os.killpg and
faking os.name; no real process is started and no model is called."""
import os
import subprocess

from bastion.agents import runtime
from bastion.llm import backbone


class _FakeProc:
    pid = 4242


def _simulate_windows(monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.delattr(os, "killpg", raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200, raising=False)


def test_runtime_kill_uses_taskkill_tree_on_windows(monkeypatch):
    _simulate_windows(monkeypatch)
    calls = []
    monkeypatch.setattr(subprocess, "run",
                        lambda argv, **kw: calls.append(argv) or subprocess.CompletedProcess(argv, 0))
    runtime._kill(_FakeProc())          # must not raise AttributeError
    assert calls == [["taskkill", "/T", "/F", "/PID", "4242"]]


def test_backbone_kill_uses_taskkill_tree_on_windows(monkeypatch):
    _simulate_windows(monkeypatch)
    calls = []
    monkeypatch.setattr(subprocess, "run",
                        lambda argv, **kw: calls.append(argv) or subprocess.CompletedProcess(argv, 0))
    backbone.kill_tree(_FakeProc())
    assert calls == [["taskkill", "/T", "/F", "/PID", "4242"]]


def test_windows_popen_gets_new_process_group(monkeypatch):
    _simulate_windows(monkeypatch)
    assert backbone.group_kwargs() == {"creationflags": 0x200}


def test_posix_kill_still_uses_killpg(monkeypatch):
    killed = []
    monkeypatch.setattr(os, "killpg", lambda pid, sig: killed.append((pid, sig)), raising=False)
    runtime._kill(_FakeProc())
    assert killed == [(4242, backbone.signal.SIGKILL)]
    assert backbone.group_kwargs() == {"start_new_session": True}
