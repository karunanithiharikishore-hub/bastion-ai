"""ITEM-25: `serve` takes the commander guardrails; ITEM-17: GET /api/report is read-only."""
import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

from conftest import SAMPLES
import bluecell.web.server as server_mod
from bluecell.cli import build_parser, cmd_serve
from bluecell.web.server import _State, _make_handler


def test_serve_parser_accepts_commander_limits():
    args = build_parser().parse_args(
        ["serve", SAMPLES, "--max-agents", "3", "--max-commander-turns", "4",
         "--budget-seconds", "120"])
    assert (args.max_agents, args.max_commander_turns, args.budget_seconds) == (3, 4, 120)


def test_serve_passes_commander_limits_to_server(monkeypatch):
    import bluecell.web
    seen = {}
    monkeypatch.setattr(bluecell.web, "serve", lambda paths, **kw: seen.update(kw) or None)
    args = build_parser().parse_args(
        ["serve", SAMPLES, "--max-agents", "3", "--max-commander-turns", "4",
         "--budget-seconds", "120"])
    cmd_serve(args)
    assert (seen["max_agents"], seen["max_commander_turns"], seen["budget_seconds"]) == (3, 4, 120)


def test_server_passes_commander_limits_to_analyze(tmp_path, monkeypatch):
    seen = []

    def fake_analyze(paths, **kw):
        seen.append(kw)
        return {"meta": {}}

    monkeypatch.setattr(server_mod, "analyze", fake_analyze)
    state = _State([SAMPLES], window=60, llm_mode="off", model="x",
                   intel_db=str(tmp_path / "intel.json"),
                   max_agents=3, max_commander_turns=4, budget_seconds=120)
    state.run_analysis()
    assert (seen[0]["max_agents"], seen[0]["max_commander_turns"], seen[0]["budget_seconds"]) == (3, 4, 120)


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    calls = []

    def fake_analyze(paths, **kw):
        calls.append(paths)
        return {"meta": {"events_ingested": 1}}

    monkeypatch.setattr(server_mod, "analyze", fake_analyze)
    state = _State([SAMPLES], window=60, llm_mode="off", model="x",
                   intel_db=str(tmp_path / "intel.json"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1], calls
    httpd.shutdown(); httpd.server_close(); state.close()


def _req(port, method, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request(method, path, body=None, headers=headers or {})
    r = conn.getresponse()
    status, data = r.status, r.read()
    conn.close()
    return status, data


def test_get_report_without_result_does_not_analyze(srv):
    port, calls = srv
    status, _ = _req(port, "GET", "/api/report")
    assert status == 404
    assert calls == []


def test_post_refresh_then_get_report_returns_result(srv):
    port, calls = srv
    status, _ = _req(port, "POST", "/api/refresh")
    assert status == 200 and len(calls) == 1
    status, data = _req(port, "GET", "/api/report")
    assert status == 200 and json.loads(data)["meta"]["result_id"]
    assert len(calls) == 1
