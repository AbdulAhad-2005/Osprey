"""
Execute OWASP ZAP with enhanced logging.

Args:
    target: Target URL
    scan_type: Type of scan (baseline, full, api)
    api_key: ZAP API key
    daemon: Run in daemon mode
    port: Port for ZAP daemon
    host: Host for ZAP daemon
    format_type: Output format (xml, json, html)
    output_file: Output file path
    additional_args: Additional ZAP arguments

Returns:
    ZAP scan results

Harvested: HexStrike `zap_scan` -> `/api/tools/zap`.
Category: web
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

TOOL_NAME = "zap_scan"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    scan_type = params.get("scan_type", "baseline")
    api_key = params.get("api_key", "")
    daemon = params.get("daemon", False)
    port = params.get("port", "8090")
    host = params.get("host", "0.0.0.0")
    format_type = params.get("format", "xml")
    output_file = params.get("output_file", "")
    additional_args = params.get("additional_args", "")
    if daemon:
        command = f"zaproxy -daemon -host {host} -port {port}"
        if api_key:
            command += f" -config api.key={api_key}"
        command = f"zaproxy -cmd -quickurl {target}"
        if format_type:
            command += f" -quickout {format_type}"
        if output_file:
            command += f" -quickprogress -dir \"{output_file}\""
        if api_key:
            command += f" -config api.key={api_key}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', scan_type: str = 'baseline', api_key: str = '', daemon: bool = False, port: str = '8090', host: str = '0.0.0.0', format: str = 'xml', output_file: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "scan_type": scan_type, "api_key": api_key, "daemon": daemon, "port": port, "host": host, "format": format, "output_file": output_file, "additional_args": additional_args}
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
