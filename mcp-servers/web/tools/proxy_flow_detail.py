"""
Full detail (both directions' headers + body) for one flow_id from proxy_flows.

Args:
    engagement_id: The engagement whose capture to read (required)
    flow_id: The flow_id from a proxy_flows row (required)

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

TOOL_NAME = "proxy_flow_detail"
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
    flow_id = params.get("flow_id")
    if not engagement_id or flow_id is None or str(flow_id).strip() == "":
        raise ValueError("proxy_flow_detail requires engagement_id= and flow_id=")
    return f"python3 {_cli_expr()} detail {shlex.quote(engagement_id)} {int(flow_id)}"


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    engagement_id: str = "",
    flow_id: int = -1,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = False,
    exec_timeout: int = 20,
) -> dict[str, Any]:
    params = {"engagement_id": engagement_id, "flow_id": flow_id, "additional_args": additional_args}
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
