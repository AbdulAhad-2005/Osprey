"""
Two-stage full-range scan: nmap -Pn -p- --min-rate <rate> port discovery,
then -sC -sV on every open port found.

Requires root (raw sockets for the high-rate full sweep) — real root in
Docker (-u 0) or via `sudo` natively. Runs the full range directly, no gate.

Args:
    target: Target IP/hostname (comma or space separated for multiple hosts)
    min_rate: SYN packets/sec for the full sweep
    output_file: Optional -oN output path (default /tmp/nmap_<target>.scan)
    extra_args: Extra flags folded into the stage-2 version/script scan

Category: network
"""

from __future__ import annotations

import re
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

TOOL_NAME = "nmap_full_port_scan"
CATEGORY = "network"


def build_command(**params: Any) -> str:
    target = normalize_multi_target(str(params.get("target", "")).strip())
    extra = apply_structural_ports(
        str(params.get("extra_args") or params.get("additional_args") or ""), params
    )
    min_rate = str(params.get("min_rate", "10000") or "10000").strip()
    out_file = str(params.get("output_file", "") or "").strip()
    if not out_file:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", target.split()[0]) if target else "target"
        out_file = f"/tmp/nmap_{safe}.scan"

    # Two-stage pattern: discover every open port at high rate, then
    # version+script-scan exactly those.
    sweep = f"nmap -Pn -p- --min-rate {min_rate} {target}"
    stage2 = (
        f"nmap -sC -sV -Pn -p "
        f"$(nmap -Pn -p- --min-rate {min_rate} {target} 2>/dev/null "
        f"| grep 'open' | cut -d '/' -f 1 | paste -sd ,) {target} -oN {out_file}"
    )
    if extra:
        stage2 = stage2.replace(" -oN ", f" {extra} -oN ")
    return (
        f"echo '== full-range port discovery =='; {sweep} 2>&1 "
        f"| grep -E '^[0-9]+/tcp' | head -100; "
        f"echo '== service/version scan on open ports =='; {stage2} 2>&1; "
        f"echo '== output =='; cat {out_file} 2>/dev/null | head -120"
    )


def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)


def run(
    target: str = "",
    min_rate: str = "10000",
    output_file: str = "",
    extra_args: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 900,
) -> dict[str, Any]:
    params = {
        "target": target, "min_rate": min_rate, "output_file": output_file,
        "extra_args": extra_args, "additional_args": additional_args,
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
