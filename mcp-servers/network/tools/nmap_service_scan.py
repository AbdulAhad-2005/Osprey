"""
Version + default-scripts scan (-sV -sC). Full raw + XML output.

Deliberately unprivileged (--unprivileged) — this is meant as a fast
version/script follow-up to a port-discovery tool, not a raw-socket scan, so
it needs no root in any execution mode.

Args:
    target: Target IP/CIDR (comma or space separated for multiple hosts)
    ports: Port range
    extra_args: Extra nmap flags
    host_timeout: Override the per-host NSE budget (auto-scales for wide
        ranges); 'none' removes it entirely

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
from _nmap_common import apply_structural_ports, normalize_multi_target, nmap_script_bound_args

TOOL_NAME = "nmap_service_scan"
CATEGORY = "network"


def build_command(**params: Any) -> str:
    target = normalize_multi_target(str(params.get("target", "")).strip())
    extra = apply_structural_ports(str(params.get("extra_args") or ""), params)
    host_timeout = str(params.get("host_timeout", "") or "").strip()

    # -sV -sC with nmap defaults (T3, 10 retries, no host/script timeout)
    # against filtered/CDN ports is a 20-40 minute hang even on a handful of
    # opens. Bound the scan so version+default-scripts stay a fast follow-up
    # to naabu, not a second full-timeout probe.
    parts = ["nmap", "-sV", "-sC", "-Pn", "--unprivileged", "-T4"]
    parts.extend(nmap_script_bound_args(extra, host_timeout=host_timeout))
    if extra:
        parts.append(extra)
    parts.append(target)
    return " ".join(part for part in parts if part)


def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)


def run(
    target: str = "",
    ports: str = "",
    extra_args: str = "",
    host_timeout: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "target": target, "ports": ports, "extra_args": extra_args, "host_timeout": host_timeout,
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
