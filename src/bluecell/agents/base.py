# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Agent framework primitives.

Every agent has two brains:
- a deterministic ``analyze`` method that always runs (stdlib-only, offline,
  testable), and
- an optional LLM ``enrich`` step that adds narrative/judgment when a Claude
  backbone is available.

This keeps the swarm fully functional with no API key while still benefiting
from real model reasoning when one is present.
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

    def system(self) -> str:
        return (
            f"You are a {self.role} on a blue team. "
            "Every analysis and deduction you make MUST be evidence-based and "
            "precise; no hallucinations should be introduced into the analysis. "
            "Use ONLY the provided evidence. Never invent or infer hosts, IPs, "
            "domains, file hashes, users, timestamps, or ATT&CK techniques that "
            "are not literally present in the evidence. If the evidence is "
            "insufficient to support a claim, say exactly that and stop. Prefer "
            "'not proven by the available logs' over a guess. Cite the concrete "
            "event detail behind each statement.")

    # ---- optional LLM enrichment -------------------------------------------
    def enrich(self, ctx: AgentContext, findings: list) -> list:
        """Optionally refine findings via the LLM backbone. Safe no-op if absent."""
        if ctx.backbone is None or not findings:
            return findings
        try:
            summary = "\n".join(
                f"- [{f.severity}] {f.title} (conf {f.confidence:.2f})"
                for f in findings[:12]
            )
            prompt = (
                f"{self.role} review. Here are your deterministic findings:\n"
                f"{summary}\n\nEVIDENCE DIGEST:\n{ctx.digest[:4000]}\n\n"
                f"In <=120 words, give a concise professional assessment: which "
                f"findings are most credible and what you'd do next. Do not add "
                f"new hosts/IPs/hashes not in the evidence."
            )
            note = ctx.backbone.complete(prompt, system=self.system(), max_tokens=400)
            if note:
                # ENFORCE grounding: flag any indicator the model cited that is
                # not actually in the evidence (hallucination guard).
                from .grounding import evidence_index, annotate
                idx = evidence_index(ctx.events, _all_techniques(ctx.events))
                note = annotate(note.strip(), idx)
                findings[0].rationale += f"\n\n[{self.name} LLM note] {note}"
        except Exception:
            pass  # LLM failure never breaks the swarm
        return findings

    # ---- driver -------------------------------------------------------------
    def run(self, ctx: AgentContext, use_llm: bool = True) -> list:
        findings = self.analyze(ctx) or []
        if use_llm:
            findings = self.enrich(ctx, findings)
        return findings


def _sev_from_score(score: int) -> str:
    return ("critical" if score >= 75 else "high" if score >= 50
            else "medium" if score >= 25 else "low")


def _all_techniques(events) -> set:
    out = set()
    for e in events:
        for t in getattr(e, "attack", []) or []:
            out.add(t)
    return out
