"""
Re-send a captured flow (from proxy_flows/proxy_flow_detail), optionally
tampered — the repeater half of the capture workflow. IDOR/auth-bypass/param-
pollution testing: pull a flow_id, override the field you want to tamper,
replay, compare the response.

Args:
    engagement_id: The engagement whose capture to read (required)
    flow_id: The flow_id to replay (required)
    method_override: Replace the HTTP method (leave empty to keep original)
    url_override: Replace the URL (leave empty to keep original)
    headers_json: JSON object of headers to override/add on top of the original
    body_override: Replace the request body (leave empty to keep original)

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

TOOL_NAME = "proxy_replay"
CATEGORY = "web"

_CLI_CONTAINER = "/home/mcpuser/mcp-servers/web/tools/_proxy_replay_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_proxy_replay_cli.py"))


def _cli_expr() -> str:
    return (
        f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} "
        f"|| echo {_CLI_FALLBACK} )"
    )


def build_command(**params: Any) -> str:
    engagement_id = str(params.get("engagement_id") or "").strip()
    flow_id = params.get("flow_id")
    if not engagement_id or flow_id is None or str(flow_id).strip() == "":
        raise ValueError("proxy_replay requires engagement_id= and flow_id=")

    headers_json = str(params.get("headers_json") or "").strip()
    if headers_json:
        try:
            json.loads(headers_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"headers_json must be valid JSON: {exc}") from exc

    args = [
        shlex.quote(engagement_id),
        str(int(flow_id)),
        shlex.quote(str(params.get("method_override") or "")),
        shlex.quote(str(params.get("url_override") or "")),
        shlex.quote(headers_json),
        shlex.quote(str(params.get("body_override") or "")),
    ]
    return f"python3 {_cli_expr()} " + " ".join(args)


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    engagement_id: str = "",
    flow_id: int = -1,
    method_override: str = "",
    url_override: str = "",
    headers_json: str = "",
    body_override: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = False,
    exec_timeout: int = 45,
) -> dict[str, Any]:
    params = {
        "engagement_id": engagement_id, "flow_id": flow_id,
        "method_override": method_override, "url_override": url_override,
        "headers_json": headers_json, "body_override": body_override,
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
