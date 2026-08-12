"""Resolve bundled-asset paths that must work in two execution modes.

Tool wrappers reference sibling helper CLIs and wordlists by a *fixed* container
path (``/home/mcpuser/mcp-servers/...``) because in Docker mode the backend
builds the command string and runs it via ``docker exec`` inside the kali-tools
container, where that path is real.

In native/local mode (the tool runs as a host subprocess via the MCP stdio server) 
that container path does not exist. ``container_or_local``
prefers the container path when present and otherwise falls back to the
repo-relative path, so the same wrapper works unmodified in both modes.
"""

from __future__ import annotations

import os


def container_or_local(container_path: str, local_path: str) -> str:
    """Return *container_path* if it exists on disk, else *local_path*."""
    return container_path if os.path.exists(container_path) else local_path
