"""
Website contact harvest — passive-OSINT SEED. Crawls the target site (shallow,
same-domain) and extracts its public identity surface: emails, phone numbers,
social profile links (+ handles) and person names. This is the natural starting
point: run it on the target, then pivot each name/email/username it finds.

Args:
    url: Target website URL (or bare domain — https:// is assumed)
    target: Alias for url
    domain: Alias for url
    depth: Crawl depth (0 = landing page only, default 1)
    max_pages: Page cap for the crawl (default 25)
    additional_args: Unused passthrough

Category: osint

Passive: only fetches the target's own public pages. No auth, no active probing.
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

TOOL_NAME = "web_contact_harvest"
CATEGORY = "osint"

_CLI = "/home/mcpuser/mcp-servers/osint/tools/_web_harvest_cli.py"


def build_command(**params: Any) -> str:
    url = str(
        params.get("url") or params.get("target") or params.get("domain") or ""
    ).strip()
    depth = str(params.get("depth", 1)).strip()
    max_pages = str(params.get("max_pages", 25)).strip()

    if not url:
        raise ValueError("web_contact_harvest requires url= (or target=/domain=)")

    return (
        f"python3 {shlex.quote(_CLI)} {shlex.quote(url)} "
        f"--depth {shlex.quote(depth)} --max-pages {shlex.quote(max_pages)}"
    )


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}
    return {
        "emails": len(data.get("emails", [])),
        "phones": len(data.get("phones", [])),
        "social": len(data.get("social", [])),
        "names": len(data.get("names", [])),
    }


def run(
    url: str = "",
    target: str = "",
    domain: str = "",
    depth: int = 1,
    max_pages: int = 25,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 180,
) -> dict[str, Any]:
    params = {
        "url": url,
        "target": target,
        "domain": domain,
        "depth": depth,
        "max_pages": max_pages,
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
