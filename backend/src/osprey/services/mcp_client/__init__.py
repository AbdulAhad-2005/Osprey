"""MCP server client, split into lifecycle/exec mixins + helpers.

MCPClient composes _LifecycleMixin, _DockerExecMixin and _RunMixin; the public
surface (MCPClient, get_mcp_client, MCPClientError, MCPServerNotRunning) is
unchanged for callers of osprey.services.mcp_client. Other module helpers live
in ._helpers and are imported directly by the mixins, not re-exported here."""

from __future__ import annotations
import asyncio
import os
from pathlib import Path
from osprey.schemas.tools import MCPServerCategory

from osprey.services.mcp_client._helpers import (
    _MCP_SERVERS_DIR,
    MCPServerNotRunning,
    MCPClientError,
)
from osprey.services.mcp_client._lifecycle import _LifecycleMixin
from osprey.services.mcp_client._exec import _DockerExecMixin
from osprey.services.mcp_client._run import _RunMixin


class MCPClient(_LifecycleMixin, _DockerExecMixin, _RunMixin):
    """Spawns and communicates with MCP server processes via stdio JSON-RPC.

    In Docker mode (default when KALI_CONTAINER env is set), tools execute
    inside the kali-tools container via ``docker exec -i``.

    In local mode (no KALI_CONTAINER), servers run as local subprocesses
    (useful for development on Kali Linux / WSL2).

    Each category maps to a FastMCP server script in ``mcp-servers/<category>/server.py``.
    """

    def __init__(self, mcp_servers_dir: Path | None = None) -> None:
        self._dir = mcp_servers_dir or _MCP_SERVERS_DIR
        self._processes: dict[MCPServerCategory, asyncio.subprocess.Process] = {}
        self._lock = asyncio.Lock()
        # Per-server request locks. In native/stdio mode all tool calls to one
        # category share a single subprocess's stdin/stdout, so concurrent
        # request/response pairs (the agent now issues tool calls in parallel)
        # would interleave on the same pipe — "readuntil() called while another
        # coroutine is already waiting". Serialize the stdio round-trip per
        # server. The docker-exec path spawns a fresh process per call and is
        # unaffected, so it stays fully parallel.
        self._req_locks: dict[MCPServerCategory, asyncio.Lock] = {}
        self._kali_container = os.getenv("KALI_CONTAINER", "")
        self._use_docker = bool(self._kali_container)
        # Cached "is the Kali container actually running" probe (see
        # _is_docker_available) so a configured-but-absent container falls back
        # to native host execution instead of erroring on every tool call.
        self._kali_running: bool | None = None
        self._kali_check_ts: float = 0.0



# Module-level singleton
_mcp_client: MCPClient | None = None


def get_mcp_client() -> MCPClient:
    global _mcp_client
    if _mcp_client is None:
        _mcp_client = MCPClient()
    return _mcp_client

__all__ = [
    "MCPClient",
    "get_mcp_client",
    "MCPClientError",
    "MCPServerNotRunning",
]
