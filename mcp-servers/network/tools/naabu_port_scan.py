"""
Fast port discovery via ProjectDiscovery naabu.

Args:
    target: IP, hostname, or CIDR
    ports: Port list/range (empty = naabu defaults / top ports)
    rate: Packets per second
    top_ports: Optional top-ports count (e.g. 100, 1000) when ports empty
    additional_args: Extra naabu flags

Category: network
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "naabu_port_scan"
CATEGORY = "network"


def build_command(**params: Any) -> str:
    target = str(params.get("target") or params.get("host") or "").strip()
    if not target:
        raise ValueError("naabu_port_scan requires target=")

    ports = str(params.get("ports") or "").strip()
    rate = str(params.get("rate") or "1000").strip()
    top_ports = str(params.get("top_ports") or "").strip()
    additional_args = str(params.get("additional_args") or "").strip()

    parts = [
        "naabu",
        "-host",
        shlex.quote(target),
        "-silent",
        "-rate",
        shlex.quote(rate),
    ]
    if ports:
        parts.extend(["-p", shlex.quote(ports)])
    elif top_ports:
        parts.extend(["-top-ports", shlex.quote(top_ports)])
    else:
        parts.extend(["-top-ports", "1000"])

    if additional_args:
        parts.append(additional_args)

    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)


def run(
    target: str = "",
    ports: str = "",
    rate: int = 1000,
    top_ports: str = "1000",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "target": target,
        "ports": ports,
        "rate": rate,
        "top_ports": top_ports,
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
