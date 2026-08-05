"""
Execute AutoRecon for comprehensive target enumeration with full parameter support.

Args:
    target: Single target to scan
    target_file: File containing multiple targets
    ports: Specific ports to scan
    output_dir: Output directory
    max_scans: Maximum number of concurrent scans
    max_port_scans: Maximum number of concurrent port scans
    heartbeat: Heartbeat interval
    timeout: Global timeout
    target_timeout: Per-target timeout
    config_file: Configuration file path
    global_file: Global configuration file
    plugins_dir: Plugins directory
    add_plugins_dir: Additional plugins directory
    tags: Plugin tags to include
    exclude_tags: Plugin tags to exclude
    port_scans: Port scan plugins to run
    service_scans: Service scan plugins to run
    reports: Report plugins to run
    single_target: Use single target directory structure
    only_scans_dir: Only create scans directory
    no_port_dirs: Don't create port directories
    nmap: Custom nmap command
    nmap_append: Arguments to append to nmap
    proxychains: Use proxychains
    disable_sanity_checks: Disable sanity checks
    disable_keyboard_control: Disable keyboard control
    force_services: Force service detection
    accessible: Enable accessible output
    verbose: Verbosity level (0-3)
    curl_path: Custom curl path
    dirbuster_tool: Directory busting tool
    dirbuster_wordlist: Directory busting wordlist
    dirbuster_threads: Directory busting threads
    dirbuster_ext: Directory busting extensions
    onesixtyone_community_strings: SNMP community strings
    global_username_wordlist: Global username wordlist
    global_password_wordlist: Global password wordlist
    global_domain: Global domain
    additional_args: Additional AutoRecon arguments

Returns:
    Comprehensive enumeration results with full configurability

Harvested: HexStrike `autorecon_scan` -> `/api/tools/autorecon`.
Category: network
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult
from _autorecon_results import parse as _collect_dir_results

TOOL_NAME = "autorecon_scan"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    output_dir = params.get("output_dir", "/tmp/autorecon")
    port_scans = params.get("port_scans", "top-100-ports")
    service_scans = params.get("service_scans", "default")
    heartbeat = params.get("heartbeat", 60)
    timeout = params.get("timeout", 300)
    additional_args = params.get("additional_args", "")
    command = f"autorecon {target} -o {output_dir} --heartbeat {heartbeat} --timeout {timeout}"
    if port_scans != "default":
        command += f" --port-scans {port_scans}"
    if service_scans != "default":
        command += f" --service-scans {service_scans}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    # AutoRecon writes findings to output_dir, not stdout — fold them back in.
    return _collect_dir_results(result)

def run(target: str = '', output_dir: str = '/tmp/autorecon', port_scans: str = 'top-100-ports', service_scans: str = 'default', heartbeat: int = 60, timeout: int = 300, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "output_dir": output_dir, "port_scans": port_scans, "service_scans": service_scans, "heartbeat": heartbeat, "timeout": timeout, "additional_args": additional_args}
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
