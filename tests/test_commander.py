# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Self-organising swarm: the Incident Commander deploys worker agents, reads
their results, follows up, respects its budget, and the orchestrator falls back
to the fixed tiered flow when it fails. Every model is a scripted fake (API
mode) or a fake ``claude`` executable (CLI mode); no real model is called."""
import json
import os
import re
import subprocess
import sys
import threading
import time

from test_autonomous_agents import _ctx, SRC
from bluecell.agents import SwarmOrchestrator
from bluecell.agents.dispatch import FileDispatchServer
from bluecell.agents.runtime import SwarmSession
from bluecell.report.render import _render_swarm

COMMANDER = "SOC Lead / Incident Commander"


def _role(body) -> str:
    if body["system"].startswith("You are the SOC Lead"):
        return COMMANDER
    return body["system"].split(" on a blue team")[0].replace("You are the ", "")


def _last_results(body) -> list:
    """The tool results the model is reading this turn (parsed JSON)."""
    msg = body["messages"][-1]
    if msg["role"] != "user" or isinstance(msg["content"], str):
        return []
    return [dict(json.loads(c["content"]), _is_error=c["is_error"])
            for c in msg["content"]]


def _use(name, args, uid="u"):
    return {"content": [{"type": "tool_use", "id": uid, "name": name, "input": args}]}


def _text(t):
    return {"content": [{"type": "text", "text": t}]}


class SwarmModel:
    """API backbone stand-in. Workers behave plausibly and file grounded
    submissions; the commander follows ``commander_script``: a list of
    functions(body) -> response, one per commander turn."""
    resolved = "api"
    model = "fake"

    def __init__(self, ctx, commander_script, worker_delay=0.0):
        self.ctx = ctx
        self.script = list(commander_script)
        self.commander_bodies = []
        self.roles_called = []
        self.systems = {}
        self.worker_delay = worker_delay
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def messages(self, body):
        role = _role(body)
        if role == COMMANDER:
            self.commander_bodies.append(body)
            return self.script.pop(0)(body)
        first = len(body["messages"]) == 1
        if first:
            self.roles_called.append(role)
            self.systems[role] = body["system"]
            with self._lock:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            time.sleep(self.worker_delay)
            with self._lock:
                self.active -= 1
            return self._worker_first_move(role, body)
        return _text(f"{role}: done")

    def _worker_first_move(self, role, body):
        inc = self.ctx.incidents[0]
        if role == "Tier-2 SOC Analyst":
            return _use("submit_verdict", {
                "incident_id": inc.id, "decision": "confirmed", "confidence": 0.9,
                "rationale": "multi-source intrusion", "evidence": [inc.events[0].event_id]})
        if role == "Tier-1 SOC Analyst":
            src = re.search(r"owns the '([^']+)' log source", body["system"]).group(1)
            ev = next(e for e in self.ctx.events if e.source == src)
            return _use("submit_finding", {
                "title": f"Suspicious {src} activity", "severity": "high",
                "confidence": 0.7, "rationale": f"see {ev.event_id}",
                "evidence": [ev.event_id], "incident_id": inc.id})
        return _use("submit_finding", {
            "title": f"{role} finding", "severity": "medium", "confidence": 0.6,
            "rationale": "grounded", "evidence": [inc.events[-1].event_id],
            "incident_id": inc.id})


def _orch(ctx, model, **kw):
    ctx.backbone = model
    return SwarmOrchestrator(ctx, orchestration="commander", **kw)


# ---------------------------------------------------------------------------
# API mode
# ---------------------------------------------------------------------------
def test_commander_deploys_agents_and_gets_results_back():
    ctx = _ctx()
    inc = ctx.incidents[0]
    seen = {}

    def triage(body):
        return _use("deploy_agents", {"agents": [
            {"role": "tier1-analyst", "source": "edr", "reason": "endpoint first"},
            {"role": "tier1-analyst", "source": "dns", "reason": "C2 check"}]})

    def verify(body):
        seen["triage"] = _last_results(body)[0]
        return _use("deploy_agent", {"role": "tier2-verifier", "reason": "verify candidates"})

    def respond(body):
        seen["verdict"] = _last_results(body)[0]
        return _use("deploy_agent", {"role": "incident-responder", "incident_id": inc.id,
                                     "reason": "confirmed; contain it"})

    def finish(body):
        return _use("finish", {"summary": f"{inc.id} confirmed and contained."})

    model = SwarmModel(ctx, [triage, verify, respond, finish,
                             lambda b: _text("closed")])
    out = _orch(ctx, model).run()

    # Results came back to the commander as tool results.
    triage_res = seen["triage"]
    assert [r["agent"] for r in triage_res["results"]] == ["soc1-edr", "soc1-dns"]
    assert triage_res["results"][0]["findings"][0]["title"] == "Suspicious edr activity"
    assert triage_res["budget"]["agents_deployed"] == 2
    v = seen["verdict"]["verdicts"][0]
    assert v["incident_id"] == inc.id and v["decision"] == "confirmed"
    assert v["decided_by"] == "agent"

    # Swarm result keeps its shape and records the commander's decisions.
    assert out["orchestration"] == "commander"
    for key in ("roster", "agent_count", "counts", "agent_runs", "tier3_skipped",
                "findings", "consensus"):
        assert key in out
    assert out["roster"][0] == {"name": "soc-lead", "role": COMMANDER, "tier": 0}
    assert out["agent_count"] == 5 and out["counts"]["autonomous_agents"] == 5
    assert out["counts"]["tier1_findings"] == 2 and out["counts"]["confirmed_incidents"] == 1
    assert out["tier3_skipped"] is None
    plan = out["commander"]["plan"]
    assert [(p["action"], p.get("role")) for p in plan] == [
        ("deploy", "tier1-analyst"), ("deploy", "tier1-analyst"),
        ("deploy", "tier2-verifier"), ("deploy", "incident-responder"), ("finish", None)]
    assert plan[0]["batch"] == plan[1]["batch"] == 1 and plan[0]["reason"] == "endpoint first"
    assert "confirmed (agent)" in plan[2]["outcome"]
    assert out["commander"]["summary"] == f"{inc.id} confirmed and contained."
    assert out["commander"]["fallback_reason"] is None
    # Headline contract: a Tier-2 agent verdict exists.
    t2 = [f for f in out["findings"] if f["tier"] == 2]
    assert t2 and t2[0]["origin"] == "agent" and t2[0]["status"] == "escalated"
    # Tier-2 saw the Tier-1 candidates and marked them.
    assert all(f["status"] == "confirmed" for f in out["findings"] if f["tier"] == 1)
    # The responder got the commander's focus in its brief.
    assert f"Focus on incident {inc.id}." in model.systems["Incident Responder"]
    md = _render_swarm(out)
    assert "Incident Commander decisions" in md and "verify candidates" in md
    assert "confirmed and contained" in md and "T0 `soc-lead`" in md


def test_commander_follow_up_uses_a_workers_result():
    ctx = _ctx()
    lead = {}

    def triage(body):
        return _use("deploy_agent", {"role": "tier1-analyst", "source": "firewall",
                                     "reason": "egress review"})

    def follow_up(body):
        finding = _last_results(body)[0]["findings"][0]
        lead["event"] = finding["evidence"][0]
        lead["id"] = finding["id"]
        return _use("deploy_agent", {
            "role": "threat-hunter", "reason": f"follow up {finding['id']}",
            "objective": f"hunt everything related to event {lead['event']}"})

    def verify(body):
        assert _last_results(body)[0]["role"] == "Threat Hunter"
        return _use("deploy_agent", {"role": "tier2-verifier", "reason": "decide"})

    model = SwarmModel(ctx, [triage, follow_up, verify,
                             lambda b: _use("finish", {"summary": "done"}),
                             lambda b: _text("closed")])
    out = _orch(ctx, model).run()
    hunt = next(p for p in out["commander"]["plan"] if p.get("role") == "threat-hunter")
    fw_event = next(e.event_id for e in ctx.events if e.source == "firewall")
    assert lead["event"] == fw_event
    assert hunt["objective"].endswith(fw_event) and lead["id"] in hunt["reason"]
    assert model.roles_called == ["Tier-1 SOC Analyst", "Threat Hunter", "Tier-2 SOC Analyst"]
    # The hunter's system prompt carried the commander's objective.
    assert f"Direction from the Incident Commander: hunt everything related to event " \
           f"{fw_event}" in model.systems["Threat Hunter"]
    assert out["orchestration"] == "commander"


def test_budget_limits_are_enforced_with_clear_tool_errors():
    ctx = _ctx()
    errors = []

    def too_many(body):
        return _use("deploy_agents", {"agents": [
            {"role": "tier1-analyst", "source": s, "reason": "triage"}
            for s in ("edr", "dns", "syslog")]})

    def bad_request(body):
        errors.append(_last_results(body)[0])
        return _use("deploy_agents", {"agents": [
            {"role": "wizard", "reason": "x"},
            {"role": "tier1-analyst", "source": "nope", "reason": "x"},
            {"role": "investigator", "reason": "x"}]})

    def fits(body):
        errors.append(_last_results(body)[0])
        return _use("deploy_agents", {"agents": [
            {"role": "tier1-analyst", "source": "edr", "reason": "triage"},
            {"role": "tier2-verifier", "reason": "verify"}]})

    def over(body):
        return _use("deploy_agent", {"role": "threat-hunter", "reason": "more"})

    def finish(body):
        errors.append(_last_results(body)[0])
        return _use("finish", {"summary": "budget spent"})

    def after_finish(body):
        return _use("deploy_agent", {"role": "forensics", "reason": "late"})

    def end(body):
        errors.append(_last_results(body)[0])
        return _text("closed")

    model = SwarmModel(ctx, [too_many, bad_request, fits, over, finish, after_finish, end])
    out = _orch(ctx, model, max_agents=2).run()
    budget_err, bad, over_err, late = errors
    assert budget_err["_is_error"] and "agent budget exceeded" in budget_err["error"]
    assert "3 requested" in budget_err["error"]
    text = " ".join(bad["problems"])
    assert "unknown role 'wizard'" in text and "needs 'source'" in text
    assert "investigator needs an 'objective'" in text
    assert "0 left" in over_err["error"] and "call finish" in over_err["error"]
    assert "case is closed" in late["error"]
    assert out["orchestration"] == "commander"
    assert out["commander"]["agents_deployed"] == 2
    assert sum(1 for r in out["agent_runs"] if r["tier"] != 0) == 2
    refused = [p for p in out["commander"]["plan"] if p["action"] == "refused"]
    assert len(refused) == 4
    assert "deploy refused" in _render_swarm(out)


def test_parallel_cap_and_wall_clock_budget():
    ctx = _ctx()
    sources = sorted({e.source for e in ctx.events})
    model = SwarmModel(ctx, [
        lambda b: _use("deploy_agents", {"agents": [
            {"role": "tier1-analyst", "source": s, "reason": "triage"} for s in sources]}),
        lambda b: _use("deploy_agent", {"role": "tier2-verifier", "reason": "verify"}),
        lambda b: _text("done")], worker_delay=0.15)
    out = _orch(ctx, model, max_parallel=2).run()
    assert out["orchestration"] == "commander"
    assert model.max_active == 2       # 5 agents in the batch, never more than 2 at once
    # Commander did not call finish: its closing text is the summary.
    assert out["commander"]["summary"] == "done" and not out["commander"]["finished"]

    # No wall-clock left: every deploy is refused, nothing runs, fixed flow takes over.
    ctx = _ctx()
    seen = []
    model = SwarmModel(ctx, [
        lambda b: _use("deploy_agent", {"role": "tier2-verifier", "reason": "verify"}),
        lambda b: seen.append(_last_results(b)[0]) or _text("gave up")])
    out = _orch(ctx, model, budget_seconds=0).run()
    assert "wall-clock budget exhausted" in seen[0]["error"]
    assert out["orchestration"] == "fixed"
    assert "deployed no agents" in out["commander"]["fallback_reason"]


def test_commander_turn_cap():
    ctx = _ctx()
    model = SwarmModel(ctx, [lambda b: _use("list_roles", {})] * 10)
    out = _orch(ctx, model, max_commander_turns=3).run()
    assert len(model.commander_bodies) == 3
    assert out["commander"]["limits"]["max_turns"] == 3
    assert out["orchestration"] == "fixed"


# ---------------------------------------------------------------------------
# Fallback to the fixed flow
# ---------------------------------------------------------------------------
def test_fallback_when_commander_fails():
    class Broken(SwarmModel):
        def messages(self, body):
            if _role(body) == COMMANDER:
                raise RuntimeError("commander backbone down")
            return super().messages(body)
    ctx = _ctx()
    model = Broken(ctx, [])
    out = _orch(ctx, model).run()
    assert out["orchestration"] == "fixed"
    reason = out["commander"]["fallback_reason"]
    assert "deployed no agents" in reason and "commander backbone down" in reason
    assert {r["tier"] for r in out["agent_runs"]} == {1, 2, 3}
    assert all(a["tier"] != 0 for a in out["roster"])
    assert "fell back to the fixed tiered flow" in _render_swarm(out)


def test_fallback_when_commander_gets_no_verdict():
    ctx = _ctx()
    model = SwarmModel(ctx, [
        lambda b: _use("deploy_agent", {"role": "tier1-analyst", "source": "edr",
                                        "reason": "triage"}),
        lambda b: _use("finish", {"summary": "looks fine"}),
        lambda b: _text("closed")])
    out = _orch(ctx, model).run()
    assert out["orchestration"] == "fixed"
    assert "without a Tier-2 agent verdict" in out["commander"]["fallback_reason"]
    assert out["commander"]["plan"][0]["agent"] == "soc1-edr"
    # The fixed flow re-ran everything from scratch: one Tier-1 agent per source.
    sources = {e.source for e in ctx.events}
    assert sum(1 for a in out["roster"] if a["tier"] == 1) == len(sources)
    t2 = [f for f in out["findings"] if f["tier"] == 2]
    assert t2 and t2[0]["origin"] == "agent"


def test_orchestration_modes_without_backbone():
    out = SwarmOrchestrator(_ctx(), use_llm=False, orchestration="auto").run()
    assert out["orchestration"] == "fixed" and out["commander"] is None
    out = SwarmOrchestrator(_ctx(), use_llm=False, orchestration="commander").run()
    assert out["orchestration"] == "fixed"
    assert out["commander"]["fallback_reason"] == "no model backbone available"
    # The deterministic report stays as it was.
    assert {r["mode"] for r in out["agent_runs"]} == {"rules"}


def test_cli_flag_reaches_the_swarm(tmp_path):
    from conftest import SAMPLES
    from bluecell.cli import build_parser, main
    args = build_parser().parse_args(["analyze", SAMPLES, "--orchestration", "fixed"])
    assert args.orchestration == "fixed"
    assert build_parser().parse_args(["serve", SAMPLES]).orchestration == "auto"
    out = tmp_path / "r.json"
    assert main(["analyze", SAMPLES, "--llm", "off", "--orchestration", "commander",
                 "--format", "json", "-o", str(out)]) == 0
    swarm = json.load(open(out))["swarm"]
    assert swarm["orchestration"] == "fixed"
    assert swarm["commander"]["fallback_reason"] == "no model backbone available"


# ---------------------------------------------------------------------------
# CLI mode: dispatch over MCP + file IPC
# ---------------------------------------------------------------------------
def test_mcp_dispatch_round_trip_through_file_ipc():
    """A real mcp_server process in --commander mode forwards deploy_agent to the
    parent's FileDispatchServer and blocks until the answer comes back."""
    ctx = _ctx()
    session = SwarmSession(ctx, seed=[])
    calls = []

    def handler(op, args):
        calls.append((op, args))
        if op == "deploy":
            time.sleep(0.5)        # the MCP call must wait for the "workers"
            return {"results": [{"agent": "soc2-lead", "verdicts": []}],
                    "budget": {"agents_deployed": 1}}
        return {"roles": [], "budget": {}}
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "deploy_agent",
                    "arguments": {"role": "tier2-verifier", "reason": "verify"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "submit_verdict", "arguments": {}}},
    ]
    tools = "case_overview,read_board,list_roles,deploy_agent,deploy_agents,finish"
    try:
        with FileDispatchServer(session.dir, handler):
            proc = subprocess.run(
                [sys.executable, "-m", "bluecell.agents.mcp_server", "--session",
                 session.dir, "--agent", "soc-lead", "--role", COMMANDER,
                 "--tools", tools, "--commander", "--dispatch-timeout", "30"],
                input="\n".join(map(json.dumps, msgs)) + "\n", capture_output=True,
                text=True, env=dict(os.environ, PYTHONPATH=SRC), timeout=60)
        replies = {r["id"]: r for r in map(json.loads, proc.stdout.splitlines())}
        names = {t["name"] for t in replies[2]["result"]["tools"]}
        assert {"deploy_agent", "deploy_agents", "finish", "list_roles"} <= names
        assert "submit_finding" not in names and "submit_verdict" not in names
        res = json.loads(replies[3]["result"]["content"][0]["text"])
        assert res["agent"] == "soc2-lead" and res["budget"] == {"agents_deployed": 1}
        assert calls == [("deploy", {"agents": [{
            "role": "tier2-verifier", "reason": "verify", "objective": None,
            "incident_id": None, "source": None}]})]
        assert replies[4]["result"]["isError"] is True     # not granted to the lead
        assert os.listdir(os.path.join(session.dir, "dispatch")) == []
    finally:
        session.close()


FAKE_CLAUDE = r'''#!{python}
"""Fake `claude -p`: starts the MCP server from --mcp-config, plays a fixed
script over it, and prints stream-json like the real CLI."""
import json, os, subprocess, sys

args = sys.argv[1:]
opt = lambda name: args[args.index(name) + 1]
with open(os.environ["FAKE_CLAUDE_LOG"], "a") as fh:
    fh.write(json.dumps({{"argv": args,
                         "mcp_timeout": os.environ.get("MCP_TOOL_TIMEOUT")}}) + "\n")
srv = json.load(open(opt("--mcp-config")))["mcpServers"]["bluecell"]
system, prompt = opt("--system-prompt"), sys.stdin.read()
p = subprocess.Popen([srv["command"]] + srv["args"], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, text=True,
                     env=dict(os.environ, **srv.get("env", {{}})))
ids = iter(range(1, 10**6))

def rpc(method, params=None):
    p.stdin.write(json.dumps({{"jsonrpc": "2.0", "id": next(ids), "method": method,
                              "params": params or {{}}}}) + "\n")
    p.stdin.flush()
    return json.loads(p.stdout.readline())["result"]

def call(name, arguments):
    return json.loads(rpc("tools/call", {{"name": name, "arguments": arguments}})
                      ["content"][0]["text"])

rpc("initialize", {{"protocolVersion": "2025-06-18"}})
if system.startswith("You are the SOC Lead"):
    roles = call("list_roles", {{}})
    t1 = call("deploy_agent", {{"role": "tier1-analyst", "source": roles["sources"][0],
                               "reason": "triage first source"}})
    t2 = call("deploy_agent", {{"role": "tier2-verifier", "reason": "verify"}})
    v = t2["verdicts"][0]
    call("finish", {{"summary": f"{{v['incident_id']}} {{v['decision']}} by {{t2['agent']}}"
                               f" after {{t1['agent']}}"}})
    result = "commander done"
elif "Tier-2 SOC Analyst" in system:
    for inc in call("case_overview", {{}})["incidents"]:
        first = call("get_incident", {{"incident_id": inc["id"]}})["events"][0].split()[0]
        call("submit_verdict", {{"incident_id": inc["id"], "decision": "dismissed",
                                "confidence": 0.8, "rationale": "approved change",
                                "evidence": [first]}})
    result = "verdicts filed"
else:
    call("case_overview", {{}})
    result = "nothing to file"
p.stdin.close()
p.wait()
print(json.dumps({{"type": "system", "subtype": "init"}}))
print(json.dumps({{"type": "result", "subtype": "success", "is_error": False,
                  "result": result, "num_turns": 3, "total_cost_usd": 0}}))
'''


class CliBackbone:
    resolved = "cli"
    model = "fake"


def test_cli_commander_end_to_end_with_fake_claude(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "claude"
    exe.write_text(FAKE_CLAUDE.format(python=sys.executable))
    exe.chmod(0o755)
    log = tmp_path / "claude.log"
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_CLAUDE_LOG", str(log))
    monkeypatch.setenv("PYTHONPATH", SRC)

    ctx = _ctx(CliBackbone())
    inc = ctx.incidents[0]
    first_source = sorted({e.source for e in ctx.events})[0]
    out = SwarmOrchestrator(ctx, orchestration="commander", budget_seconds=600).run()

    assert out["orchestration"] == "commander", out["commander"]
    assert out["commander"]["summary"] == \
        f"{inc.id} dismissed by soc2-lead after soc1-{first_source}"
    assert [p["agent"] for p in out["commander"]["plan"] if p["action"] == "deploy"] == \
        [f"soc1-{first_source}", "soc2-lead"]
    lead = out["agent_runs"][0]
    assert lead["agent"] == "soc-lead" and lead["mode"] == "autonomous"
    assert {"list_roles", "deploy_agent", "finish"} <= set(lead["tools_used"])
    t2 = next(f for f in out["findings"] if f["tier"] == 2)
    assert t2["origin"] == "agent" and t2["status"] == "dismissed"
    assert out["tier3_skipped"]

    runs = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(runs) == 3                       # commander + two workers
    for r in runs:                              # CLI hardening flags kept
        argv = r["argv"]
        assert "--strict-mcp-config" in argv and "--no-session-persistence" in argv
        assert argv[argv.index("--tools") + 1] == ""
    lead_argv = runs[0]["argv"]
    allowed = lead_argv[lead_argv.index("--allowedTools") + 1].split(",")
    assert "mcp__bluecell__deploy_agents" in allowed
    assert "mcp__bluecell__submit_finding" not in allowed
    assert runs[0]["mcp_timeout"] == str((600 + 300) * 1000)
    assert runs[1]["mcp_timeout"] is None


# ---------------------------------------------------------------------------
# Robustness: IPC races, cleanup, hung/late workers, thread safety
# ---------------------------------------------------------------------------
def test_dispatch_client_withdraws_request_on_timeout(tmp_path):
    from bluecell.agents.dispatch import FileDispatchClient
    client = FileDispatchClient(str(tmp_path), timeout=0.5)
    out = client("deploy", {"agents": []})          # nobody is serving
    assert "timed out" in out["error"] and "may still be running" not in out["error"]
    # The unclaimed request was withdrawn, so a server started later never runs it.
    assert os.listdir(tmp_path / "dispatch") == []
    calls = []
    with FileDispatchServer(str(tmp_path), lambda op, a: calls.append(op) or {}):
        time.sleep(0.5)
    assert calls == []


def test_dispatch_client_returns_when_session_is_closed(tmp_path):
    import shutil
    from bluecell.agents.dispatch import FileDispatchClient
    client = FileDispatchClient(str(tmp_path), timeout=30)
    threading.Timer(0.3, shutil.rmtree, args=(tmp_path / "dispatch",)).start()
    t0 = time.monotonic()
    out = client("list_roles", {})
    assert time.monotonic() - t0 < 5 and "closed the case" in out["error"]


def test_dispatch_server_survives_bad_requests_and_handler_errors(tmp_path):
    from bluecell.agents.dispatch import FileDispatchClient, dispatch_dir

    def handler(op, args):
        if op == "boom":
            raise ValueError("bad dispatch")
        return {"ok": op}
    os.makedirs(dispatch_dir(str(tmp_path)))
    (tmp_path / "dispatch" / "junk.req.json").write_text("{not json")
    client = FileDispatchClient(str(tmp_path), timeout=10)
    with FileDispatchServer(str(tmp_path), handler) as srv:
        assert client("boom", {}) == {"error": "ValueError: bad dispatch"}
        assert client("list_roles", {}) == {"ok": "list_roles"}   # still serving
        assert srv._thread.is_alive()
    # The junk request was answered with an error; nothing else is left behind.
    left = os.listdir(tmp_path / "dispatch")
    assert left == ["junk.res.json"]
    assert "unreadable" in json.loads((tmp_path / "dispatch" / left[0]).read_text())["error"]


def test_dispatch_server_stop_rejects_queued_requests(tmp_path):
    """Parallel MCP calls queue behind a running deploy; when the commander
    stops, the queued ones get an error instead of hanging their callers."""
    from bluecell.agents.dispatch import FileDispatchClient
    release = threading.Event()

    def handler(op, args):
        if op == "deploy":
            release.wait(5)
        return {"ok": op}
    client = FileDispatchClient(str(tmp_path), timeout=20)
    srv = FileDispatchServer(str(tmp_path), handler, join_timeout=0.2).start()
    answers = {}
    t1 = threading.Thread(target=lambda: answers.update(a=client("deploy", {})))
    t1.start()
    time.sleep(0.6)                                  # deploy is now in flight
    t2 = threading.Thread(target=lambda: answers.update(b=client("finish", {})))
    t2.start()
    time.sleep(0.6)                                  # finish is queued behind it
    assert srv.stop() is False                       # deploy still running
    t2.join(5)
    assert "case is closed" in answers["b"]["error"]
    release.set()
    t1.join(5)
    assert answers["a"] == {"ok": "deploy"}          # the in-flight call completes


def test_late_worker_results_are_discarded_after_close():
    """If the commander stops while a deploy is running (CLI: its process timed
    out), the workers' results must not be merged into the finished swarm."""
    from bluecell.agents.commander import Dispatcher
    ctx = _ctx()
    started, release = threading.Event(), threading.Event()

    class Slow(SwarmModel):
        def messages(self, body):
            started.set()
            release.wait(5)
            return super().messages(body)
    ctx.backbone = Slow(ctx, [])
    orch = SwarmOrchestrator(ctx, orchestration="commander")
    session = SwarmSession(ctx, seed=[])
    try:
        disp = Dispatcher(orch, ctx, session)
        out = {}
        t = threading.Thread(target=lambda: out.update(r=disp.handle("deploy", {
            "agents": [{"role": "tier1-analyst", "source": "edr", "reason": "x"}]})))
        t.start()
        assert started.wait(5)
        disp.close()
        release.set()
        t.join(10)
    finally:
        session.close()
    assert "results were discarded" in out["r"]["error"]
    assert orch.tier1 == [] and orch.roster == [] and orch.agent_runs == []
    assert disp.plan == []
    assert "case is closed" in disp.handle("deploy", {"agents": [
        {"role": "tier2-verifier", "reason": "x"}]})["error"]


def test_queued_worker_is_skipped_when_budget_runs_out(monkeypatch):
    """Timeouts are sized when a worker starts, not when the batch is queued; a
    worker still waiting behind the parallel cap when time runs out is skipped."""
    from bluecell.agents import commander
    monkeypatch.setattr(commander, "MIN_WORKER_SECONDS", 0.6)
    ctx = _ctx()
    model = SwarmModel(ctx, [
        lambda b: _use("deploy_agents", {"agents": [
            {"role": "tier1-analyst", "source": "edr", "reason": "a"},
            {"role": "tier1-analyst", "source": "dns", "reason": "b"}]}),
        lambda b: _text("out of time")], worker_delay=0.6)
    out = _orch(ctx, model, max_parallel=1, budget_seconds=1.0).run()
    plan = out["commander"]["plan"]
    assert plan[0]["outcome"].startswith("autonomous")
    assert plan[1]["outcome"].startswith("skipped") and "budget" in plan[1]["outcome"]
    assert out["orchestration"] == "fixed"           # no verdict -> fixed flow
    skipped = next(r for r in out["commander"]["plan"] if r.get("agent") == "soc1-dns")
    assert skipped["outcome"].startswith("skipped")


def test_one_verifier_per_batch():
    ctx = _ctx()
    seen = []
    model = SwarmModel(ctx, [
        lambda b: _use("deploy_agents", {"agents": [
            {"role": "tier2-verifier", "reason": "a"},
            {"role": "tier2-verifier", "reason": "b"}]}),
        lambda b: seen.append(_last_results(b)[0]) or
        _use("deploy_agent", {"role": "tier2-verifier", "reason": "verify"}),
        lambda b: _use("finish", {"summary": "ok"}),
        lambda b: _text("closed")])
    out = _orch(ctx, model).run()
    assert any("at most one tier2-verifier" in p for p in seen[0]["problems"])
    assert out["orchestration"] == "commander" and out["commander"]["agents_deployed"] == 1
