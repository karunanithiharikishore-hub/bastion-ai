# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Agentic layer: Tier-1/Tier-2/Tier-3 blue-team agents that investigate as
autonomous, tool-using model agents (see runtime.py), organised either by an
LLM Incident Commander (commander.py) or by the fixed tiered flow
(orchestrator.py), with rule-based fallbacks when no model is available."""
from .base import Agent, Finding, AgentContext
from .orchestrator import SwarmOrchestrator, run_swarm
from .analyst import ai_analyze, build_evidence_brief

__all__ = ["Agent", "Finding", "AgentContext", "SwarmOrchestrator", "run_swarm",
           "ai_analyze", "build_evidence_brief"]
