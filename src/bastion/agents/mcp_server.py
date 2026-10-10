# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Stdio MCP server exposing the investigation toolbox to one agent.

The keyless backbone runs each specialist as its own ``claude -p`` process; that
process drives its own agent loop (plan -> call tool -> read result -> decide)
and reaches Bastion AI's evidence only through this server. Stdlib-only: newline
delimited JSON-RPC 2.0, implementing initialize, tools/list and tools/call.

    python -m bastion.agents.mcp_server --session DIR --agent NAME --role ROLE \
        [--tools a,b,c] [--source-scope SOURCE]

With ``--commander`` the server also offers the Incident Commander's dispatch
tools (deploy_agent, ...); it cannot run agents itself, so those calls are
relayed to the parent orchestrator through files in ``DIR/dispatch/`` (see
``dispatch.py``) and the tool call blocks until the workers finish.

``DIR`` holds ``ctx.pkl`` (the pickled AgentContext written by the runtime) and
``board.jsonl`` (the shared board). ``--tools`` limits which tools this agent
is offered (default: every tool except Tier-2's submit_verdict). Accepted
findings, verdicts and the tool-call audit
trail are written to ``DIR/<agent-slug>.out.json`` after every call, so the parent
can collect them even if the agent stops early.
"""
from __future__ import annotations

import argparse
import json
import os
import pickle
import sys

from .dispatch import CommanderToolbox, FileDispatchClient
from .toolbox import Blackboard, SecurityToolbox, BASE_TOOLS, file_slug

SERVER_NAME = "bastion"
DEFAULT_PROTOCOL = "2025-06-18"


def _tools_for_mcp(box: SecurityToolbox) -> list:
    return [{"name": t["name"], "description": t["description"],
             "inputSchema": t["input_schema"]} for t in box.specs()]


def _flush(box: SecurityToolbox, out_path: str) -> None:
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"findings": box.findings, "verdicts": list(box.verdicts.values()),
                   "calls": box.calls}, fh, default=str)
    os.replace(tmp, out_path)


def _error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def handle(msg: dict, box: SecurityToolbox, out_path: str):
    """Return the JSON-RPC response for one message, or None for notifications."""
    if not isinstance(msg, dict):
        return _error(None, -32600, "invalid request: expected a JSON object")
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        return None
    if method == "initialize":
        version = (msg.get("params") or {}).get("protocolVersion") or DEFAULT_PROTOCOL
        result = {"protocolVersion": version,
                  "capabilities": {"tools": {"listChanged": False}},
                  "serverInfo": {"name": SERVER_NAME, "version": "1.0"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": _tools_for_mcp(box)}
    elif method == "tools/call":
        params = msg.get("params") or {}
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return _error(mid, -32602, "invalid params: 'name' must be a string")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return _error(mid, -32602, "invalid params: 'arguments' must be an object")
        text = box.call(params["name"], args)
        _flush(box, out_path)
        is_error = text.startswith('{"error"')
        result = {"content": [{"type": "text", "text": text}], "isError": is_error}
    else:
        return _error(mid, -32601, f"method not found: {method}")
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--agent", required=True)
    ap.add_argument("--role", required=True)
    ap.add_argument("--tools", default=",".join(BASE_TOOLS))
    ap.add_argument("--source-scope", default=None)
    ap.add_argument("--commander", action="store_true",
                    help="serve the Incident Commander's dispatch tools; dispatch "
                         "calls are forwarded to the parent via DIR/dispatch/")
    ap.add_argument("--dispatch-timeout", type=float, default=3900.0)
    args = ap.parse_args(argv)

    with open(os.path.join(args.session, "ctx.pkl"), "rb") as fh:
        state = pickle.load(fh)
    board = Blackboard(os.path.join(args.session, "board.jsonl"))
    kw = dict(board_seed=state.get("seed"),
              tools=[t for t in args.tools.split(",") if t],
              source_scope=args.source_scope)
    if args.commander:
        box = CommanderToolbox(state["ctx"], args.agent, args.role, board,
                               dispatch=FileDispatchClient(args.session,
                                                           args.dispatch_timeout), **kw)
    else:
        box = SecurityToolbox(state["ctx"], args.agent, args.role, board, **kw)
    out_path = os.path.join(args.session, f"{file_slug(args.agent)}.out.json")
    _flush(box, out_path)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            resp = handle(msg, box, out_path)
        except Exception as exc:  # one bad message must not kill the server
            mid = msg.get("id") if isinstance(msg, dict) else None
            resp = _error(mid, -32603, f"internal error: {type(exc).__name__}: {exc}")
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
