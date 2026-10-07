# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Agentic layer: rule-based Tier-1/Tier-2 triage, then Tier-3 specialists that
investigate as autonomous, tool-using model agents (see runtime.py)."""
from .base import Agent, Finding, AgentContext
from .orchestrator import SwarmOrchestrator, run_swarm
from .analyst import ai_analyze, build_evidence_brief

__all__ = ["Agent", "Finding", "AgentContext", "SwarmOrchestrator", "run_swarm",
           "ai_analyze", "build_evidence_brief"]
