"""ITEM-19: serve --llm api|cli with no backbone must warn, and report the mode actually in use."""
import json
import threading
import urllib.request

import pytest

from conftest import SAMPLES
from bastion.llm.backbone import LLMBackbone
from bastion.web import server


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("BASTION_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path / "runs"))
    # no `claude` CLI either: the backbone must be genuinely unavailable
    monkeypatch.setattr(LLMBackbone, "_cli_available", lambda self: False)


def _serve_once(monkeypatch, llm):
    """Run serve() on an ephemeral port, GET /api/meta once, then stop it (no model calls)."""
    seen = {}
    real_make = server._make_server

    def make(host, port, handler):
        httpd = real_make(host, 0, handler)
        real_serve = httpd.serve_forever

        def fetch_then_stop():
            url = f"http://127.0.0.1:{httpd.server_address[1]}/api/meta"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            seen["meta"] = json.loads(opener.open(url, timeout=10).read())
            httpd.shutdown()

        def serve_forever():
            threading.Thread(target=fetch_then_stop, daemon=True).start()
            real_serve()
        httpd.serve_forever = serve_forever
        return httpd

    monkeypatch.setattr(server, "_make_server", make)
    server.serve([SAMPLES], port=0, llm_mode=llm)
    return seen["meta"]


@pytest.mark.parametrize("mode", ["api", "cli"])
def test_explicit_backbone_missing_warns_and_reports_off(monkeypatch, capsys, mode):
    meta = _serve_once(monkeypatch, mode)
    out, err = capsys.readouterr()
    assert meta["llm_mode"] == "off"
    assert "llm=off" in out and f"llm={mode}" not in out
    assert f"--llm {mode} requested" in err


def test_auto_backbone_missing_reports_off_without_warning(monkeypatch, capsys):
    meta = _serve_once(monkeypatch, "auto")
    out, err = capsys.readouterr()
    assert meta["llm_mode"] == "off"
    assert "llm=off" in out
    assert "WARNING" not in err
