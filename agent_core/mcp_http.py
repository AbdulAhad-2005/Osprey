"""Optional in-process MCP gateway, mounted at /mcp when OSPREY_MCP_HTTP is set.

A separate standalone process (platform-mcp/server.py's own
MCP_TRANSPORT=streamable-http mode, started by hand) still works too, but
most setups don't need a second port/service: the backend is already
running, so mounting the same MCP tool surface onto its own FastAPI app
means a URL-only MCP client just points at http://localhost:9000/mcp — no
extra script, no extra container, no extra port to manage.

Loaded under its own distinct module identity (not tools.py's load_server()
cache) so this gateway's session globals (_SESSION_TARGET,
_SESSION_ENGAGEMENT_ID, ... in platform-mcp/_gateway_core.py) stay
independent of the backend's OWN embedded gateway instance (agent_runner.py /
foreground_chat.py's GUI-chat path) — two unrelated consumers must not share
one mutable session.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

from agent_core.net import resolve_api_base_url

_MODULE_NAME = "_osprey_mounted_mcp_http"
_server: Any = None


def mcp_http_enabled() -> bool:
    """Whether to mount the MCP gateway. Docker's `env_file: .env` pushes
    OSPREY_MCP_HTTP straight into os.environ, but a locally-run (no Docker)
    backend never loads .env into the real process environment — nothing in
    backend/ calls python-dotenv's load_dotenv() the way cli/main.py does —
    so this also reads the dotenv file directly for that case.
    """
    value = os.environ.get("OSPREY_MCP_HTTP", "").strip()
    if not value:
        from dotenv import dotenv_values

        explicit = os.environ.get("OSPREY_ENV_FILE", "").strip()
        dotenv_path = Path(explicit).resolve() if explicit else Path(__file__).resolve().parents[1] / ".env"
        value = (dotenv_values(dotenv_path).get("OSPREY_MCP_HTTP") or "").strip()
    return value.lower() in ("1", "true", "yes")


def load_mcp_server() -> Any:
    """Import platform-mcp/server.py once and return its (fully tool-
    registered) MCPServer instance, ready to mount with .streamable_http_app().
    """
    global _server
    if _server is not None:
        return _server

    os.environ.setdefault("PENTEST_API_BASE", resolve_api_base_url())
    os.environ.setdefault("PENTEST_MCP_QUIET", "1")

    # agent_core/mcp_http.py -> repo root (or /app in Docker) -> platform-mcp/
    # — same depth-1 relationship agent_core/tools.py's loader already relies
    # on, which holds in both layouts because agent_core/ keeps its own name
    # when copied into the backend image (unlike backend/src -> /app/src).
    mcp_dir = Path(__file__).resolve().parents[1] / "platform-mcp"
    mcp_dir_str = str(mcp_dir)
    if mcp_dir_str not in sys.path:
        sys.path.insert(0, mcp_dir_str)

    spec = importlib.util.spec_from_file_location(_MODULE_NAME, mcp_dir / "server.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load the MCP gateway for in-process mounting")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_MODULE_NAME] = module
    spec.loader.exec_module(module)

    _server = module.mcp
    return _server
