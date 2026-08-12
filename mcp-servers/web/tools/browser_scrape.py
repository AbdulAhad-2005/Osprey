"""Headless-browser scraper — render a JS/SPA page in real Chromium and extract
the attack surface static crawlers miss (client-side routes, XHR/fetch APIs,
forms, cookies-with-flags, screenshot).

Thin build_command wrapper around ``_browser_scrape_cli.py`` (Playwright worker
that runs inside the Kali container).
"""

from __future__ import annotations

import shlex
import sys
import time
import uuid
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "browser_scrape"
CATEGORY = "web"

from _core.paths import container_or_local

_CLI = container_or_local(
    "/home/mcpuser/mcp-servers/web/tools/_browser_scrape_cli.py",
    str(Path(__file__).resolve().with_name("_browser_scrape_cli.py")),
)
_SHOT_DIR = "/tmp/pentest/screenshots"


def build_command(**params: Any) -> str:
    url = str(params.get("url") or params.get("target") or "").strip()
    if not url:
        raise ValueError("browser_scrape requires url=")
    if "://" not in url:
        url = "https://" + url
    timeout_ms = int(params.get("timeout_ms") or 30000)
    wait_until = str(params.get("wait_until") or "networkidle").strip()
    max_items = int(params.get("max_items") or 300)
    screenshot = str(params.get("screenshot", "true")).strip().lower() in ("1", "true", "yes", "on")
    additional_args = str(params.get("additional_args") or "").strip()

    parts = [
        "python3", shlex.quote(_CLI),
        "--url", shlex.quote(url),
        "--timeout-ms", str(timeout_ms),
        "--wait-until", shlex.quote(wait_until),
        "--max-items", str(max_items),
    ]
    if screenshot:
        shot = f"{_SHOT_DIR}/scrape_{int(time.time())}_{uuid.uuid4().hex[:6]}.png"
        parts += ["--screenshot", shlex.quote(shot)]
    cmd = f"bash -c \"mkdir -p {shlex.quote(_SHOT_DIR)}; " + " ".join(parts) + "\""
    if additional_args:
        cmd = cmd[:-1] + f" {additional_args}\""
    return cmd


def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)


def run(
    url: str = "",
    target: str = "",
    timeout_ms: int = 30000,
    wait_until: str = "networkidle",
    max_items: int = 300,
    screenshot: bool = True,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 180,
) -> dict[str, Any]:
    params = {
        "url": url or target, "timeout_ms": timeout_ms, "wait_until": wait_until,
        "max_items": max_items, "screenshot": screenshot, "additional_args": additional_args,
    }
    return run_tool(
        TOOL_NAME, build_command(**params), params=params, timeout=exec_timeout,
        use_cache=use_cache, use_recovery=use_recovery, parse_fn=parse,
    )
