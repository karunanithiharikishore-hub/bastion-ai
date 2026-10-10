# Bastion AI - Blue-Team Log Intelligence
# Author & Copyright: Harikishore Karunanithi
# SPDX-License-Identifier: MIT  (use and share freely, but keep this attribution)
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Bastion AI — Blue-Team Log Intelligence.

A local, read-only, multi-agent system that ingests security logs from many
sources, normalizes them to a compact unified schema, correlates events across
sources, maps activity to MITRE ATT&CK, then runs a swarm of tiered blue-team
agents (Junior/Senior SOC, Incident Responder, Forensics, Threat Hunter,
Malware Analyst, Threat Intel, Security Engineer, Vulnerability Analyst) that
verify and reconcile findings into an incident report with RCA storyline, IOCs,
and a prioritized threat-hunt checklist.

Built by Harikishore Karunanithi. Licensed under MIT — attribution required.
"""
import os as _os

from . import provenance as _prov


def _legacy_compat() -> None:
    """Bastion AI was called BlueCell: honour old BLUECELL_* settings and an existing
    ~/.bluecell data dir (cache, runs, intel) unless the new BASTION_* ones are set."""
    for k, v in list(_os.environ.items()):
        if k.startswith("BLUECELL_"):
            _os.environ.setdefault("BASTION_" + k[len("BLUECELL_"):], v)
    old = _os.path.join(_os.path.expanduser("~"), ".bluecell")
    if _os.path.isdir(old) and not _os.path.exists(_os.path.join(_os.path.expanduser("~"), ".bastion")):
        for env, sub in (("BASTION_CACHE_DIR", "cache"), ("BASTION_RUNS_DIR", "runs"),
                         ("BASTION_INTEL_DB", "intel.json")):
            if _os.path.exists(_os.path.join(old, sub)):
                _os.environ.setdefault(env, _os.path.join(old, sub))


_legacy_compat()

__author__ = _prov.AUTHOR
__copyright__ = _prov.COPYRIGHT
__license__ = "MIT"
__version__ = "0.13.0"

# Attribution is asserted via the LICENSE / AUTHORS / source headers, not a
# runtime kill-switch. No integrity gate runs on import.
