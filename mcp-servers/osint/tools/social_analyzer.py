"""
social-analyzer — discover and rate a username's presence across 1000+ social
sites, extracting profile metadata. Keyless. Complements sherlock/maigret with a
detection-confidence filter.

Args:
    username: Username / handle to search for
    target: Alias for username
    filter_level: Detection filter — good | best | all (default good)
    additional_args: Extra social-analyzer flags (any)

Category: osint

Passive: requests public profile pages only; `good` filter reduces false hits.
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

TOOL_NAME = "social_analyzer"
CATEGORY = "osint"


def build_command(**params: Any) -> str:
    username = str(params.get("username") or params.get("target") or "").strip()
    filter_level = str(params.get("filter_level") or "good").strip()
    additional_args = str(params.get("additional_args") or "").strip()

    if not username:
        raise ValueError("social_analyzer requires username= (or target=)")

    parts = [
        "social-analyzer",
        "--username", shlex.quote(username),
        "--metadata",
        "--output", "json",
        "--filter", shlex.quote(filter_level),
    ]
    if additional_args:
        parts.append(additional_args)
    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        data = json.loads(raw)
        detected = data.get("detected", []) if isinstance(data, dict) else []
        return {"detected": len(detected)}
    except (json.JSONDecodeError, ValueError):
        return {"detected": 0}


def run(
    username: str = "",
    target: str = "",
    filter_level: str = "good",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "username": username,
        "target": target,
        "filter_level": filter_level,
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
