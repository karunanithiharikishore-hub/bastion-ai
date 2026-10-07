"""
============================================================================
 BlueCell — Blue-Team Log Intelligence
 Author & Copyright:  Harikishore Karunanithi
 SPDX-License-Identifier: MIT
 WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
============================================================================

Authorship + attribution integrity.

This module is the single source of truth for who built BlueCell. Every entry
point verifies it at startup. If the author attribution is removed or altered,
:func:`enforce` HALTS the program and points to where the watermark lives so
the rightful owner can restore it.

HONEST LIMITATIONS (stated plainly, by design):
- This detects casual removal/rebranding and refuses to run when tampered.
- It is NOT unbreakable DRM. Anyone with the source can edit files; a
  determined actor could patch this check too. The real, enforceable
  protection is the MIT license + copyright below: you may use and share this
  software, but you must keep this attribution.
"""
from __future__ import annotations

import hashlib
import os

# --- Immutable authorship facts (do not remove; removal halts the program) ---
AUTHOR = "Harikishore Karunanithi"
PROJECT = "BlueCell"
PROVENANCE_ID = "bluecell-provenance-v1"
COPYRIGHT = f"Copyright (c) 2026 {AUTHOR}. Licensed under MIT — attribution required."
WATERMARK = f"BLUECELL::AUTHOR::{AUTHOR.replace(' ', '-')}"

# sha256("Harikishore Karunanithi|BlueCell|bluecell-provenance-v1")
EXPECTED_SIGNATURE = "1868ce0cc2384c21a1a6fd6473a92ea73705e9f1e4aa8df21735bc416dc5eb73"

# Files that MUST carry the watermark header. Used both to inform the owner and
# to detect stripping of attribution from the tree.
WATERMARK_LOCATIONS = (
    "src/bluecell/provenance.py",
    "src/bluecell/__init__.py",
    "LICENSE",
    "NOTICE",
    "AUTHORS",
    "README.md",
)


def signature() -> str:
    canonical = f"{AUTHOR}|{PROJECT}|{PROVENANCE_ID}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_integrity() -> tuple[bool, str]:
    """Return (ok, reason). ok=False means the attribution was tampered with."""
    if AUTHOR.strip() != "Harikishore Karunanithi":
        return False, "AUTHOR constant was altered."
    if signature() != EXPECTED_SIGNATURE:
        return False, "Provenance signature mismatch (author/project changed)."
    if WATERMARK != "BLUECELL::AUTHOR::Harikishore-Karunanithi":
        return False, "WATERMARK constant was altered."
    return True, "ok"


def _repo_root() -> str:
    # provenance.py -> bluecell -> src -> repo root
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def scan_repo() -> list[str]:
    """Return watermark files that are missing or no longer contain the author.

    Best-effort: if the repo layout isn't present (e.g. installed as a wheel),
    missing files are ignored rather than reported as tampering.
    """
    root = _repo_root()
    problems = []
    for rel in WATERMARK_LOCATIONS:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            continue  # not a source checkout; skip silently
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                if AUTHOR not in fh.read():
                    problems.append(rel)
        except OSError:
            continue
    return problems


def banner() -> str:
    bar = "=" * 62
    return (
        f"{bar}\n"
        f"  {PROJECT} - Blue-Team Log Intelligence\n"
        f"  Built by {AUTHOR}\n"
        f"  {COPYRIGHT}\n"
        f"{bar}"
    )


def enforce(strict: bool = True) -> None:
    """Soft attribution check at startup.

    Earlier versions hard-halted the program if the author attribution was
    removed. That was attribution-as-kill-switch, which is both trivially
    bypassed and inappropriate for MIT-licensed software — the enforceable
    protection is the LICENSE, not a runtime gate. This now only prints a
    non-fatal warning if the attribution looks altered, and never exits.
    """
    import sys
    ok, reason = verify_integrity()
    if not ok:
        print(f"[bluecell] note: authorship attribution appears altered "
              f"({reason}). Please keep the author credit per the MIT license.",
              file=sys.stderr)

