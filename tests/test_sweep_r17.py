"""ITEM-17 / ITEM-18: Messages API errors surface as BackboneUnavailable (never raw
ValueError/HTTPException), a non-object body is rejected, and 5xx is retried like 429.
Offline: urlopen is patched, time.sleep is patched."""
import http.client
import io
import urllib.error

import pytest

from bluecell.llm import backbone as bb
from bluecell.llm.backbone import BackboneUnavailable, LLMBackbone


class _Resp:
    def __init__(self, body=b'{"content": [], "usage": {}}', read_exc=None):
        self._body, self._read_exc = body, read_exc

    def __enter__(self): return self
    def __exit__(self, *a): pass

    def read(self):
        if self._read_exc:
            raise self._read_exc
        return self._body


class _BadBodyErr(urllib.error.HTTPError):
    """HTTPError whose body cannot be read (connection dropped mid-body)."""
    def __init__(self, code):
        super().__init__("u", code, "x", {}, None)

    def read(self, *a):
        raise http.client.IncompleteRead(b"")


def _err(code, retry_after=None):
    hdrs = {"retry-after": retry_after} if retry_after else {}
    return urllib.error.HTTPError("u", code, "x", hdrs, io.BytesIO(b"{}"))


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


@pytest.mark.parametrize("resp", [
    _Resp(body=b"<html>captive portal</html>"),               # JSONDecodeError
    _Resp(body=b"\xff\xfe\x00bad"),                           # UnicodeDecodeError
    _Resp(read_exc=http.client.IncompleteRead(b"partial")),   # dropped mid-body
    _Resp(body=b"[1, 2, 3]"),                                 # list payload
])
def test_bad_success_body_is_backbone_unavailable(monkeypatch, resp):
    b, _, _ = _bb(monkeypatch, [resp])
    with pytest.raises(BackboneUnavailable):
        b.messages({})


def test_unreadable_error_body_is_backbone_unavailable(monkeypatch):
    b, _, _ = _bb(monkeypatch, [_BadBodyErr(400)])
    with pytest.raises(BackboneUnavailable, match="400") as exc:
        b.messages({})
    assert exc.value.status == 400


@pytest.mark.parametrize("code", [500, 502, 503, 504])
def test_transient_5xx_is_retried(monkeypatch, code):
    b, calls, sleeps = _bb(monkeypatch, [_err(code), _Resp()])
    assert b.messages({})["content"] == []
    assert len(calls) == 2 and len(sleeps) == 1
