"""
Custom nmap flags (LLM escape hatch). Full raw + XML output.

Always runs privileged — real root in Docker (-u 0) or via `sudo` natively —
so -sS/-O/any flag combination just works with no privileged= param to
remember. An explicit scan-type flag the caller wrote (e.g. deliberately
choosing -sT to be gentle against a fragile target) is still honored as-is;
only the *default* when none was given is a real SYN scan instead of a
forced downgrade.

Args:
    target: Target IP/CIDR (comma or space separated for multiple hosts)
    flags: Custom nmap flags
    host_timeout: Override the per-host NSE budget (auto-scales for -p-/wide
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
from _nmap_common import (
    apply_structural_ports,
    nmap_has_scripts,
    nmap_script_bound_args,
    normalize_multi_target,
    normalize_nmap_flags,
)

TOOL_NAME = "nmap_custom_scan"
CATEGORY = "network"


def build_command(**params: Any) -> str:
    target = normalize_multi_target(str(params.get("target", "")).strip())
    # `extra`: the same "any of these three, then structural ports" resolution
    # every nmap tool uses — kept only as the *fallback* below (matches the
    # original command_builder behavior exactly): if the caller passed
    # `flags` explicitly, that raw value wins over the ports-augmented
    # `extra`, since `flags` is meant to be the full, deliberate flag string
    # for this escape-hatch tool; `extra` only fills in when `flags` was
    # never set at all.
    extra = str(
        params.get("extra_args") or params.get("additional_args") or params.get("flags") or ""
    ).strip()
    extra = apply_structural_ports(extra, params)
    host_timeout = str(params.get("host_timeout", "") or "").strip()

    flags = normalize_nmap_flags(str(params.get("flags", extra)).strip(), target, privileged=True)
    if nmap_has_scripts(flags):
        bound = nmap_script_bound_args(flags, host_timeout=host_timeout)
        if bound:
            flags = f"{flags} {' '.join(bound)}"
    parts = ["nmap", flags, target]
    return " ".join(part for part in parts if part)


def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)


def run(
    target: str = "",
    flags: str = "",
    host_timeout: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "target": target, "flags": flags, "host_timeout": host_timeout,
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
        sudo=True,
    )
