"""BUG-WEB-5: long non-ASCII upload names must stage under a truncated, filesystem-safe name."""
import os

from bastion.web.server import _State

NAME_MAX = 255  # bytes on Linux and macOS


def _state():
    return _State([], window=60, llm_mode="off", model="x", intel_db=None)


def test_emoji_name_truncated_by_bytes_keeps_extension():
    name = _State._safe_name(_state(), "\U0001F600" * 150 + ".log")
    assert name.endswith(".log")
    assert len(name.encode()) <= 150 + len(".log")
    name.encode("utf-8")  # no split UTF-8 sequence


def test_cjk_name_fits_name_max_with_dedupe_suffix():
    state = _state()
    token = state.stage_reset()
    for _ in range(12):  # forces __N suffixes on the same long name
        state.stage_add("中" * 150 + ".log", "x", token=token)
    names = os.listdir(state.stages[token][0])
    assert len(names) == 12 and len(set(names)) == 12
    assert all(len(n.encode()) <= NAME_MAX for n in names)
    assert all(n.endswith(".log") for n in names)
    state.close()
