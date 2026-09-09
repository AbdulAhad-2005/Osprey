"""
List/filter traffic captured by proxy_start, across every request sent through
it since it started — not scoped to one browser_flow step sequence.

Args:
    engagement_id: The engagement whose capture to read (required)
    host: Substring filter on request host
    method: Exact filter on HTTP method (GET/POST/...)
    contains: Substring filter on the full URL
    min_status: Only flows with status_code >= this
    limit: Max rows returned (most recent first, default 100)

Category: webapp
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

TOOL_NAME = "proxy_flows"
CATEGORY = "web"

_CLI_CONTAINER = "/home/mcpuser/mcp-servers/web/tools/_proxy_query_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_proxy_query_cli.py"))


def _cli_expr() -> str:
    return (
        f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} "
        f"|| echo {_CLI_FALLBACK} )"
    )


def build_command(**params: Any) -> str:
    engagement_id = str(params.get("engagement_id") or "").strip()
    if not engagement_id:
        raise ValueError("proxy_flows requires engagement_id=")
    parts = [f"python3 {_cli_expr()} list", shlex.quote(engagement_id)]
    if str(params.get("host") or "").strip():
        parts.append(f"--host {shlex.quote(str(params['host']).strip())}")
    if str(params.get("method") or "").strip():
        parts.append(f"--method {shlex.quote(str(params['method']).strip())}")
    if str(params.get("contains") or "").strip():
        parts.append(f"--contains {shlex.quote(str(params['contains']).strip())}")
    if params.get("min_status"):
        parts.append(f"--min-status {int(params['min_status'])}")
    if params.get("limit"):
        parts.append(f"--limit {int(params['limit'])}")
    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    engagement_id: str = "",
    host: str = "",
    method: str = "",
    contains: str = "",
    min_status: int = 0,
    limit: int = 100,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = False,
    exec_timeout: int = 30,
) -> dict[str, Any]:
    params = {
        "engagement_id": engagement_id, "host": host, "method": method,
        "contains": contains, "min_status": min_status, "limit": limit,
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
