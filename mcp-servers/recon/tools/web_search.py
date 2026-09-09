"""
Free general web search (DuckDuckGo HTML endpoint) — no API key required.

Use for anything the internal catalog can't answer from a target directly:
fresh CVE PoC/writeup hunting once a version is fingerprinted (searchsploit's
offline Exploit-DB lags real disclosures and misses most GitHub-only PoCs),
current technique research, product/vendor advisories. Read-only, no target
contact — safe to run unconditionally, not gated.

Args:
    query: Search query, e.g. "CVE-2026-12345 exploit poc" or "Apache 2.4.58 RCE"
    limit: Max results to return (1-25, default 10)
    additional_args: Unused passthrough for platform freeform field

Category: recon
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "web_search"
CATEGORY = "recon"

# Runtime-resolved in the shell (inside the Kali container where the filesystem
# is real): commands are built in the backend but executed via docker exec.
_CLI_CONTAINER = "/home/mcpuser/mcp-servers/recon/tools/_web_search_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_web_search_cli.py"))


def _cli_expr() -> str:
    return (
        f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} "
        f"|| echo {_CLI_FALLBACK} )"
    )


def build_command(**params: Any) -> str:
    query = str(params.get("query") or "").strip()
    limit = params.get("limit", 10)

    if not query:
        raise ValueError("web_search requires query=")

    return (
        f"python3 {_cli_expr()} "
        f"{shlex.quote(query)} {shlex.quote(str(limit))}"
    )


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    query: str = "",
    limit: int = 10,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 45,
) -> dict[str, Any]:
    params = {
        "query": query,
        "limit": limit,
        "additional_args": additional_args,
    }
    command = build_command(**params)
    return run_tool(
        TOOL_NAME,
        command,
        params=params,
        timeout=exec_timeout,
        use_cache=use_cache,
        use_recovery=use_recovery,
        parse_fn=parse,
    )
