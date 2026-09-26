# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Local web dashboard (stdlib-only, read-only, binds to localhost)."""
from .server import serve

__all__ = ["serve"]
