"""
Maigret — deep username search across 3000+ sites, extracting profile data
(names, bios, linked accounts). Keyless. Richer than sherlock, slower.

Args:
    username: Username / handle to search for
    target: Alias for username
    timeout: Per-site request timeout in seconds (default 10)
    top_sites: Limit to the N most popular sites for speed (default 500)
    additional_args: Extra maigret flags (any)

Category: osint

Passive: requests public profile pages only. Extracted names/links are leads.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "maigret"
CATEGORY = "osint"


def build_command(**params: Any) -> str:
    username = str(params.get("username") or params.get("target") or "").strip()
    timeout = str(params.get("timeout") or 10).strip()
    top_sites = str(params.get("top_sites") or 500).strip()
    additional_args = str(params.get("additional_args") or "").strip()

    if not username:
        raise ValueError("maigret requires username= (or target=)")

    parts = [
        "maigret",
        shlex.quote(username),
        "--no-color",
        "--timeout", shlex.quote(timeout),
        "--top-sites", shlex.quote(top_sites),
    ]
    if additional_args:
        parts.append(additional_args)
    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    text = result.raw_stdout or ""
    hits = [ln for ln in text.splitlines() if "http" in ln]
    return {"found": len(hits)}


def run(
    username: str = "",
    target: str = "",
    timeout: int = 10,
    top_sites: int = 500,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "username": username,
        "target": target,
        "timeout": timeout,
        "top_sites": top_sites,
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
