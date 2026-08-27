"""
Execute angr for symbolic execution and binary analysis.

Args:
    binary: Binary to analyze
    script_content: Custom angr script content
    find_address: Address to find during symbolic execution
    avoid_addresses: Comma-separated addresses to avoid
    analysis_type: Type of analysis (symbolic, cfg, static)
    additional_args: Additional arguments

Returns:
    Symbolic execution and binary analysis results

Category: binary
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "angr_symbolic_execution"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    import os
    import tempfile

    binary = params.get("binary", "")
    script_content = params.get("script_content", "")
    find_address = params.get("find_address", "")
    avoid_addresses = params.get("avoid_addresses", "")
    analysis_type = params.get("analysis_type", "symbolic")
    additional_args = params.get("additional_args", "")
    fd, script_file = tempfile.mkstemp(suffix=".py", prefix="angr_")
    with os.fdopen(fd, "w") as f:
        if script_content:
            f.write(script_content)
        else:
            avoid_list = [a.strip() for a in avoid_addresses.split(",") if a.strip()]
            f.write("#!/usr/bin/env python3\nimport angr\n")
            f.write(f"project = angr.Project({binary!r}, auto_load_libs=False)\n")
            f.write(f"print('Loaded binary:', {binary!r})\n")
            if analysis_type == "symbolic":
                f.write("state = project.factory.entry_state()\n")
                f.write("simgr = project.factory.simulation_manager(state)\n")
                f.write(f"find_addr = {find_address!r} or None\n")
                f.write(f"avoid_addrs = {avoid_list!r}\n")
                f.write(
                    "if find_addr:\n"
                    "    simgr.explore(find=find_addr, avoid=avoid_addrs)\n"
                    "    if simgr.found:\n"
                    "        print('Found solution!')\n"
                    "        print(simgr.found[0].posix.dumps(0))\n"
                    "    else:\n"
                    "        print('No solution found')\n"
                )
            elif analysis_type == "cfg":
                f.write("cfg = project.analyses.CFGFast()\n")
                f.write("print('CFG nodes:', len(cfg.graph.nodes()))\n")
    command = f"python3 {script_file}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(binary: str, script_content: str = '', find_address: str = '', avoid_addresses: str = '', analysis_type: str = 'symbolic', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"binary": binary, "script_content": script_content, "find_address": find_address, "avoid_addresses": avoid_addresses, "analysis_type": analysis_type, "additional_args": additional_args}
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
