"""
holehe — check which of 120+ websites have an account registered to an email
address, via their password-reset / signup flows. Keyless, passive.

Args:
    email: Email address to check
    target: Alias for email
    only_used: Only print sites where the email IS registered (default true)
    additional_args: Extra holehe flags (any)

Category: osint

holehe reveals account *existence*, not passwords or breach contents.
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

TOOL_NAME = "holehe"
CATEGORY = "osint"


def build_command(**params: Any) -> str:
    email = str(params.get("email") or params.get("target") or "").strip()
    only_used = params.get("only_used", True)
    additional_args = str(params.get("additional_args") or "").strip()

    if not email or "@" not in email:
        raise ValueError("holehe requires a valid email= (or target=)")

    parts = ["holehe", "--no-color"]
    if only_used in (True, "true", "1", 1):
        parts.append("--only-used")
    if additional_args:
        parts.append(additional_args)
    parts.append(shlex.quote(email))
    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    text = result.raw_stdout or ""
    used = [ln for ln in text.splitlines() if ln.strip().startswith("[+]")]
    return {"accounts": len(used)}


def run(
    email: str = "",
    target: str = "",
    only_used: bool = True,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 180,
) -> dict[str, Any]:
    params = {
        "email": email,
        "target": target,
        "only_used": only_used,
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
