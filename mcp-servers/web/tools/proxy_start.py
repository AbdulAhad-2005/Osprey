"""
Start full-session passive traffic capture (mitmdump) for an engagement.

Idempotent — safe to call again mid-engagement, returns the existing instance
instead of starting a duplicate. Once running, point browser_flow/
browser_scrape at it with proxy_port=<port from this call's response>, or
route platform_shell curl/sqlmap through it with -x http://127.0.0.1:<port>
-k (see skills/web/traffic-capture.md). Captures EVERYTHING sent through it
across as many separate calls as you make, unlike browser_flow's own
captured_requests which is scoped to one step sequence.

Args:
    engagement_id: This engagement's id (required — scopes the port/log/pidfile
        so concurrent engagements on the same container don't collide)

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

TOOL_NAME = "proxy_start"
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
        raise ValueError("proxy_start requires engagement_id=")
    return f"python3 {_cli_expr()} start {shlex.quote(engagement_id)}"


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
    exec_timeout: int = 20,
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
