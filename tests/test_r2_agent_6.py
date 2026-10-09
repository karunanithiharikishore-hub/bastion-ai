# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-AGENT-6: an API-driver run with zero tool calls (refusal or empty reply)
must fail and fall back to rules, as the CLI driver already does."""
from test_autonomous_agents import ScriptedModel, _ctx

from bluecell.agents.roles import JuniorSocAnalyst
from bluecell.agents.runtime import SwarmSession


def _run_with_reply(content):
    ctx = _ctx(ScriptedModel([content]))
    session = SwarmSession(ctx, seed=[])
    try:
        agent = JuniorSocAnalyst("firewall")
        findings = agent.run(ctx, use_llm=True, session=session)
    finally:
        session.close()
    return agent.last_run, findings


def test_refusal_without_tool_calls_falls_back_to_rules():
    run, findings = _run_with_reply([{"type": "text", "text": "I can't help with that."}])
    assert run["mode"] == "fallback (rules)"
    assert run["error"] == "agent made no tool calls"
    assert run["tool_calls"] == 0
    assert findings and all(f.origin == "rules" for f in findings)


def test_empty_reply_falls_back_to_rules():
    run, findings = _run_with_reply([])
    assert run["mode"] == "fallback (rules)"
    assert run["error"] == "agent made no tool calls"
    assert findings and all(f.origin == "rules" for f in findings)
