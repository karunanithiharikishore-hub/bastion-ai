"""BlueCell — Blue-Team Log Intelligence.

A local, read-only multi-agent pipeline that ingests security logs from many
sources, normalizes them to a compact unified schema, correlates events across
sources, maps activity to MITRE ATT&CK, reconstructs an incident storyline
(RCA), and emits IOCs plus a prioritized threat-hunt checklist.

Design goals:
- Deterministic core (parse -> normalize -> compress -> correlate -> map ->
  IOC) that runs with the Python standard library only, so it works and is
  fully testable with no network and no API key.
- Optional LLM enrichment (narrative RCA storyline) via a hybrid backbone:
  the local `claude` CLI (keyless) or the Anthropic API (keyed). If neither is
  available the pipeline still produces a deterministic storyline.
"""

__version__ = "0.1.0"
