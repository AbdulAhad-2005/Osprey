"""
Stop full-session traffic capture for an engagement and free its port.

Always run this at engagement end — a leaked mitmdump process holds its port
across engagements and shows up as a stale/confusing "already running" on
the next proxy_start for a different engagement_id sharing the container.

Args:
    engagement_id: The engagement whose capture proxy to stop

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

TOOL_NAME = "proxy_stop"
CATEGORY = "web"

_CLI_CONTAINER = "/home/mcpuser/mcp-servers/web/tools/_proxy_ctl.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_proxy_ctl.py"))


def _cli_expr() -> str:
    # Double-quoted at BOTH levels: the inner echo args (so a fallback path
    # with spaces, e.g. a Windows checkout path, survives as one shell word
    # going in) AND the outer $(...) substitution itself (bash word-splits a
    # command substitution's *output* on whitespace at its point of use
    # regardless of how the inner command was quoted).
    container, fallback = shlex.quote(_CLI_CONTAINER), shlex.quote(_CLI_FALLBACK)
    return f'"$( [ -f {container} ] && echo {container} || echo {fallback} )"'


def build_command(**params: Any) -> str:
    engagement_id = str(params.get("engagement_id") or "").strip()
    if not engagement_id:
        raise ValueError("proxy_stop requires engagement_id=")
    return f"python3 {_cli_expr()} stop {shlex.quote(engagement_id)}"


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    engagement_id: str = "",
    additional_args: str = "",
    use_recovery: bool = False,
    use_cache: bool = False,
    exec_timeout: int = 15,
) -> dict[str, Any]:
    params = {"engagement_id": engagement_id, "additional_args": additional_args}
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
