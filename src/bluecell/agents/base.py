# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Agent framework primitives.

``Agent.analyze`` is the rule-based brain (stdlib-only, offline, testable).
The model-driven brain lives in ``runtime.AutonomousAgent``, which every swarm
role extends: it investigates with tools when a backbone is available and falls
back to ``analyze`` when not.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Finding:
    """A single claim produced by an agent."""
    agent: str                      # agent name
    role: str                       # role label
    tier: int                       # 1=triage, 2=verify, 3=specialist/command
    title: str
    severity: str                   # low|medium|high|critical
    confidence: float               # 0.0 - 1.0
    rationale: str
    incident_id: Optional[str] = None
    attack: list = field(default_factory=list)
    evidence: list = field(default_factory=list)     # event_ids / IOC values
    recommended_action: Optional[str] = None
    status: str = "proposed"        # proposed|confirmed|dismissed|escalated
    verified_by: list = field(default_factory=list)  # agent names that reviewed
    intel_refs: list = field(default_factory=list)
    origin: str = "rules"           # rules | agent (model-driven, tool-using)

    @property
    def id(self) -> str:
        basis = f"{self.agent}|{self.incident_id}|{self.title}"
        return "F-" + hashlib.sha1(basis.encode()).hexdigest()[:10]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        return d


@dataclass
class AgentContext:
    """Shared, read-only inputs handed to every agent (the 'Truth Graph')."""
    events: list
    incidents: list
    iocs: dict
    digest: str
    intel_store: object = None
    backbone: object = None         # LLMBackbone or None

    def incident_digest(self, incident, max_lines: int = 120) -> str:
        from ..pipeline.compress import compress
        return compress(incident.events, max_lines=max_lines)


class Agent:
    """Base class. Subclasses implement ``analyze`` and optionally ``system``."""

    role = "generic-agent"
    tier = 1

    def __init__(self, name: Optional[str] = None, model: str = "claude-sonnet-5"):
        self.name = name or self.role
        self.model = model

    # ---- to be overridden ---------------------------------------------------
    def analyze(self, ctx: AgentContext) -> list:
        """Deterministic analysis. Return a list[Finding]. Must not require LLM."""
        raise NotImplementedError

    # ---- driver -------------------------------------------------------------
    def run(self, ctx: AgentContext, use_llm: bool = True) -> list:
        return self.analyze(ctx) or []


def _sev_from_score(score: int) -> str:
    return ("critical" if score >= 75 else "high" if score >= 50
            else "medium" if score >= 25 else "low")
