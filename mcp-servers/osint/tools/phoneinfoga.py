"""
PhoneInfoga — passive OSINT on a phone number: country, carrier, line type and
public footprint (search-engine dork URLs). Keyless local scanners.

Args:
    phone: Phone number in international E.164 form (e.g. +14155552671)
    target: Alias for phone
    additional_args: Extra phoneinfoga flags (any)

Category: osint
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

TOOL_NAME = "phoneinfoga"
CATEGORY = "osint"


def build_command(**params: Any) -> str:
    phone = str(params.get("phone") or params.get("target") or "").strip()
    additional_args = str(params.get("additional_args") or "").strip()

    if not phone:
        raise ValueError("phoneinfoga requires phone= (E.164, or target=)")

    parts = ["phoneinfoga", "scan", "-n", shlex.quote(phone)]
    if additional_args:
        parts.append(additional_args)
    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    text = result.raw_stdout or ""
    return {"lines": len([ln for ln in text.splitlines() if ln.strip()])}


def run(
    phone: str = "",
    target: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 120,
) -> dict[str, Any]:
    params = {
        "phone": phone,
        "target": target,
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
