"""CLI package for Osprey.

Initializing stdout/stderr to UTF-8 here ensures rich's glyphs (✓ ✗ — …) never
crash on Windows consoles that default to cp1252, regardless of how the CLI is
launched (``python -m cli`` or the ``osprey`` console script).
"""

from __future__ import annotations

import sys


def _init_console_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


_init_console_encoding()
