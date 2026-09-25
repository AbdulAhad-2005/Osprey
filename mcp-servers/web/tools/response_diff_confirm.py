"""
Deterministic response-differential confirmation: fetch two requests (a
boolean-TRUE vs boolean-FALSE blind-injection payload, an authenticated vs
unauthenticated request, before vs after a tampered param) and report a
real, computed diff — status codes, length delta, a line diff — instead of
an agent's own impression. The grounding a platform_file_finding
(evidence_kind='reproduction') claim needs for a blind-SQLi or
authorization-bypass finding: cite THIS tool's own observation and quote
its `diff` field.

Args:
    url_a: First URL (e.g. the boolean-TRUE / baseline request)
    url_b: Second URL (e.g. the boolean-FALSE / tampered request)
    method: HTTP method for both (default GET)
    headers_json: JSON object of request headers, applied to both
    body_a: Request body for url_a (non-GET/HEAD)
    body_b: Request body for url_b (non-GET/HEAD)
    timeout: Seconds before giving up, per request (default 15)

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

TOOL_NAME = "response_diff_confirm"
CATEGORY = "web"

_CLI_CONTAINER = "/home/mcpuser/mcp-servers/web/tools/_response_diff_confirm_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_response_diff_confirm_cli.py"))


def _cli_expr() -> str:
    return (
        f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} "
        f"|| echo {_CLI_FALLBACK} )"
    )


def build_command(**params: Any) -> str:
    url_a = str(params.get("url_a") or "").strip()
    url_b = str(params.get("url_b") or "").strip()
    if not url_a or not url_b:
        raise ValueError("response_diff_confirm requires url_a= and url_b=")

    headers_json = str(params.get("headers_json") or "").strip()
    if headers_json:
        try:
            json.loads(headers_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"headers_json must be valid JSON: {exc}") from exc

    args = [
        shlex.quote(url_a),
        shlex.quote(url_b),
        shlex.quote(str(params.get("method") or "GET")),
        shlex.quote(headers_json),
        shlex.quote(str(params.get("body_a") or "")),
        shlex.quote(str(params.get("body_b") or "")),
        shlex.quote(str(params.get("timeout") or "15")),
    ]
    return f"python3 {_cli_expr()} " + " ".join(args)


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    url_a: str = "",
    url_b: str = "",
    method: str = "GET",
    headers_json: str = "",
    body_a: str = "",
    body_b: str = "",
    timeout: int = 15,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = False,
    exec_timeout: int = 45,
) -> dict[str, Any]:
    params = {
        "url_a": url_a, "url_b": url_b, "method": method,
        "headers_json": headers_json, "body_a": body_a, "body_b": body_b,
        "timeout": timeout, "additional_args": additional_args,
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
