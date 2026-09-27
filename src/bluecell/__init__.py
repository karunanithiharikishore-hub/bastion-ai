# BlueCell - Blue-Team Log Intelligence
# Author & Copyright: Harikishore Karunanithi
# SPDX-License-Identifier: MIT  (use and share freely, but keep this attribution)
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BlueCell — Blue-Team Log Intelligence.

A local, read-only, multi-agent system that ingests security logs from many
sources, normalizes them to a compact unified schema, correlates events across
sources, maps activity to MITRE ATT&CK, then runs a swarm of tiered blue-team
agents (Junior/Senior SOC, Incident Responder, Forensics, Threat Hunter,
Malware Analyst, Threat Intel, Security Engineer, Vulnerability Analyst) that
verify and reconcile findings into an incident report with RCA storyline, IOCs,
and a prioritized threat-hunt checklist.

Built by Harikishore Karunanithi. Licensed under MIT — attribution required.
"""
from . import provenance as _prov

__author__ = _prov.AUTHOR
__copyright__ = _prov.COPYRIGHT
__license__ = "MIT"
__version__ = "0.13.0"

# Attribution is asserted via the LICENSE / AUTHORS / source headers, not a
# runtime kill-switch. No integrity gate runs on import.
