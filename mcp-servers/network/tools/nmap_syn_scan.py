"""
TCP SYN scan (-sS) — real raw-socket SYN scan, never a connect-scan fallback.

Always runs privileged: in Docker, docker-exec runs it as real root
(-u 0, handled by mcp_client.py); natively (no Kali container), `sudo -n`
requests the same via `_core.executor`. There's no unprivileged mode to
fall back to and no per-call param needed to request it.

Args:
    target: Target IP/CIDR (comma or space separated for multiple hosts)
    ports: Port range
    timing: Timing template (T0-T5)
    extra_args: Extra nmap flags

Category: network
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult
from _nmap_common import apply_structural_ports, normalize_multi_target

TOOL_NAME = "nmap_syn_scan"
CATEGORY = "network"


def build_command(**params: Any) -> str:
    target = normalize_multi_target(str(params.get("target", "")).strip())
    extra = apply_structural_ports(str(params.get("extra_args") or ""), params)
    parts = ["nmap", "-sS"]
    timing = params.get("timing")
    if timing:
        t = str(timing).lstrip("Tt")
        parts.append(f"-T{t}")
    if extra:
        parts.append(extra)
    parts.append(target)
    return " ".join(part for part in parts if part)


def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)


def run(
    target: str = "",
    ports: str = "",
    timing: str = "",
    extra_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {"target": target, "ports": ports, "timing": timing, "extra_args": extra_args}
    command = build_command(**params)
    return run_tool(
        TOOL_NAME,
        command,
        params=params,
        timeout=exec_timeout,
        use_cache=use_cache,
        use_recovery=use_recovery,
        parse_fn=parse,
        sudo=True,
    )
