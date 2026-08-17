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
    """Return *container_path* when the platform executes commands inside the Kali
    container (KALI_CONTAINER set), else *local_path*.

    The existence check is NOT done here: command strings are built in the backend
    process but executed via ``docker exec`` inside the Kali container, and the two
    environments see different filesystems. In Docker mode the fixed container path
    is the only one that exists where the command actually runs; in native/local mode
    (no KALI_CONTAINER) the repo-relative path is correct because the tool runs as a
    host subprocess with the backend's filesystem view.
    """
    if os.getenv("KALI_CONTAINER"):
        return container_path
    return local_path
