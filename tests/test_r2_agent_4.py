"""R2 agent 4: a transient API 429 is retried, not a swarm-wide halt."""
import io
import urllib.error

import pytest

from bastion.llm import backbone as bb
from bastion.llm.backbone import LLMBackbone, BackboneUnavailable


def _err(code, retry_after=None):
    hdrs = {"retry-after": retry_after} if retry_after else {}
    return urllib.error.HTTPError("u", code, "x", hdrs,
                                  io.BytesIO(b'{"type":"rate_limit_error"}'))


class _Resp:
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def read(self): return b'{"content": [], "usage": {}}'


def _bb(monkeypatch, outcomes):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    calls, sleeps = [], []
    def fake(req, timeout):
        calls.append(timeout)
        o = outcomes[min(len(calls) - 1, len(outcomes) - 1)]
        if isinstance(o, Exception):
            raise o
        return o
    monkeypatch.setattr(bb.urllib.request, "urlopen", fake)
    monkeypatch.setattr(bb.time, "sleep", sleeps.append)
    return LLMBackbone(mode="api"), calls, sleeps


def test_transient_429_is_retried(monkeypatch):
    b, calls, sleeps = _bb(monkeypatch, [_err(429, "7"), _Resp()])
    assert b.messages({})["content"] == []
    assert len(calls) == 2 and sleeps == [7.0]


def test_persistent_429_raises_after_bounded_retries(monkeypatch):
    b, calls, sleeps = _bb(monkeypatch, [_err(429)])
    with pytest.raises(BackboneUnavailable, match="429"):
        b.messages({})
    assert len(calls) == bb._RETRIES + 1 and len(sleeps) == bb._RETRIES


def test_retry_does_not_outlive_budget(monkeypatch):
    b, calls, sleeps = _bb(monkeypatch, [_err(429, "20"), _Resp()])
    with pytest.raises(BackboneUnavailable, match="429"):
        b.messages({}, timeout=5)
    assert len(calls) == 1 and sleeps == []


def test_other_http_errors_are_not_retried(monkeypatch):
    b, calls, _ = _bb(monkeypatch, [_err(400)])
    with pytest.raises(BackboneUnavailable, match="400"):
        b.messages({})
    assert len(calls) == 1


@pytest.mark.parametrize("bad", ["-5", "nan", "inf"])
def test_bad_retry_after_falls_back_to_backoff(monkeypatch, bad):
    # R3-AGENT-6: time.sleep(-5) / sleep(nan) raised ValueError instead of retrying.
    b, calls, sleeps = _bb(monkeypatch, [_err(429, bad), _Resp()])
    assert b.messages({})["content"] == []
    assert sleeps == [2]
