"""Declarative browser-flow driver — execute a step sequence in one real Chromium
session (login, authenticated navigation, business-logic tests). The LLM authors
the steps; the whole flow runs in a single tool call.

Thin build_command wrapper around ``_browser_flow_cli.py`` (Playwright worker).
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

from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "browser_flow"
CATEGORY = "web"

_CLI = "/home/mcpuser/mcp-servers/web/tools/_browser_flow_cli.py"
_SHOT_DIR = "/tmp/pentest/screenshots"


def build_command(**params: Any) -> str:
    url = str(params.get("url") or params.get("target") or "").strip()
    steps = params.get("steps")
    if isinstance(steps, str):
        steps_json = steps.strip()
        # Validate it parses; fail early with a clear message.
        try:
            json.loads(steps_json)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"browser_flow steps= must be valid JSON list: {exc}")
    elif isinstance(steps, (list, tuple)):
        steps_json = json.dumps(list(steps))
    else:
        raise ValueError("browser_flow requires steps= (JSON list of step objects)")

    timeout_ms = int(params.get("timeout_ms") or 30000)
    additional_args = str(params.get("additional_args") or "").strip()

    parts = [
        "python3", shlex.quote(_CLI),
        "--steps", shlex.quote(steps_json),
        "--timeout-ms", str(timeout_ms),
        "--screenshot-dir", shlex.quote(_SHOT_DIR),
    ]
    if url:
        if "://" not in url:
            url = "https://" + url
        parts += ["--url", shlex.quote(url)]
    cmd = f"bash -c \"mkdir -p {shlex.quote(_SHOT_DIR)}; " + " ".join(parts) + "\""
    if additional_args:
        cmd = cmd[:-1] + f" {additional_args}\""
    return cmd


def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)


def run(
    steps: Any = "",
    url: str = "",
    target: str = "",
    timeout_ms: int = 30000,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = False,
    exec_timeout: int = 240,
) -> dict[str, Any]:
    params = {
        "url": url or target, "steps": steps, "timeout_ms": timeout_ms,
        "additional_args": additional_args,
    }
    return run_tool(
        TOOL_NAME, build_command(**params), params=params, timeout=exec_timeout,
        use_cache=use_cache, use_recovery=use_recovery, parse_fn=parse,
    )
