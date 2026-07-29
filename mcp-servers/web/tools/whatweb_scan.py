"""
Execute WhatWeb to fingerprint web technologies, CMS, frameworks, and libraries.

WhatWeb identifies technologies from HTTP headers, HTML content, JavaScript
patterns, and known URL paths. It detects 1800+ plugins including CMS platforms,
JavaScript frameworks, web servers, analytics tools, and more.

Args:
    target: Target URL or domain
    aggression: Detection aggressiveness (1=passive, 4=aggressive). Default 1.
    verbose: Enable verbose output for deeper detection
    additional_args: Extra WhatWeb CLI flags

Returns:
    Structured technology findings from WhatWeb fingerprinting

Harvested: HexStrike `whatweb_scan` -> `/api/tools/whatweb`.
Category: web
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "whatweb_scan"
CATEGORY = "web"

# Technology categories that WhatWeb plugin names map to for security analysis
SECURITY_RELEVANT_CATEGORIES = {
    "cms": "CMS",
    "framework": "Framework",
    "javascript": "JavaScript Library",
    "web-server": "Web Server",
    "programming-language": "Programming Language",
    "database": "Database",
    "analytics": "Analytics",
    "widget": "Widget",
    "media": "Media",
    "hosting": "Hosting",
    "ssl": "SSL/TLS",
    "country": "Geolocation",
    "ip": "IP Address",
}


def build_command(**params: Any) -> str:
    """Build WhatWeb CLI command with JSON output for structured parsing."""
    target = params.get("target", "")
    aggression = params.get("aggression", "1")
    verbose = params.get("verbose", False)
    additional_args = params.get("additional_args", "")

    parts = ["whatweb"]

    # JSON output to stdout for parsing
    parts.append("--log-json=-")

    # Aggression level (1=passive, 2-4=increasingly aggressive)
    if aggression and str(aggression) != "1":
        parts.append(f"-a {aggression}")

    # Verbose mode for deeper detection
    if verbose:
        parts.append("-v")

    # User agent
    parts.append('--user-agent="PentestPlatform/1.0"')

    # Additional flags
    if additional_args:
        parts.append(additional_args)

    # Target (last argument)
    # Ensure target has scheme
    target_str = str(target).strip()
    if target_str and not target_str.startswith(("http://", "https://")):
        target_str = f"https://{target_str}"
    parts.append(shlex.quote(target_str))

    return " ".join(parts)


def _extract_tech_findings(data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract structured technology findings from WhatWeb JSON output."""
    findings = []
    seen = set()

    for result in data:
        target = result.get("target", "")
        plugins = result.get("plugins", {})
        http_status = result.get("http_status", 0)

        for plugin_name, plugin_data in plugins.items():
            # Skip metadata-only plugins
            if plugin_name in ("IP", "Country", "UncommonHeaders", "Allow"):
                continue

            # Extract version if available
            version = ""
            versions = plugin_data.get("version", [])
            if versions:
                version = versions[0] if isinstance(versions, list) else str(versions)

            # Extract string details
            strings = plugin_data.get("string", [])
            string_detail = strings[0] if strings else ""

            # Build finding key for dedup
            finding_key = f"{plugin_name}:{version}".lower()
            if finding_key in seen:
                continue
            seen.add(finding_key)

            finding = {
                "technology": plugin_name,
                "version": version,
                "string_detail": string_detail,
                "target": target,
                "http_status": http_status,
                "module": plugin_data.get("module", []),
            }
            findings.append(finding)

    return findings


def parse(result: ToolResult) -> dict[str, Any]:
    """Parse WhatWeb JSON output into structured findings."""
    stdout = result.raw_stdout or ""
    stderr = result.raw_stderr or ""

    # WhatWeb exits 0 even when it never connected (e.g. "ERROR Opening: ...
    # execution expired"), leaving stdout as an empty JSON array. Surface that
    # distinctly so it isn't mistaken for "scanned, zero technologies found".
    connect_error = ""
    if "ERROR Opening" in stderr or "execution expired" in stderr:
        connect_error = stderr.strip().splitlines()[-1][:300]

    # Try to parse JSON output
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        # WhatWeb sometimes mixes JSON with non-JSON lines
        # Try to find JSON array in output
        lines = stdout.strip().split("\n")
        json_lines = []
        bracket_depth = 0
        in_json = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("["):
                in_json = True
            if in_json:
                json_lines.append(line)
                bracket_depth += stripped.count("[") - stripped.count("]")
                if bracket_depth <= 0 and json_lines:
                    break
        if json_lines:
            try:
                data = json.loads("\n".join(json_lines))
            except json.JSONDecodeError:
                return {
                    "findings": [],
                    "raw_output": stdout,
                    "error": "Failed to parse WhatWeb output",
                }
        else:
            return {
                "findings": [],
                "raw_output": stdout,
                "error": "No JSON data found in WhatWeb output",
            }

    if not isinstance(data, list):
        data = [data]

    findings = _extract_tech_findings(data)

    # Build summary
    tech_list = [f["technology"] for f in findings]
    versions = {f["technology"]: f["version"] for f in findings if f["version"]}

    result_dict: dict[str, Any] = {
        "findings": findings,
        "technologies_detected": tech_list,
        "versions": versions,
        "targets_scanned": [r.get("target", "") for r in data],
        "total_technologies": len(findings),
    }
    if connect_error and not findings:
        result_dict["error"] = f"WhatWeb could not connect: {connect_error}"
    # WhatWeb has a known quirk (some installs/versions) of exiting non-zero
    # after already writing valid --log-json=- output to stdout — e.g. a Ruby
    # logging error on stream close that fires AFTER the JSON was flushed.
    # The response's top-level `success` flag is set purely from returncode
    # (see mcp_client.py) and stays as reported by the platform — this note
    # exists so an operator seeing success:false doesn't discard genuinely
    # valid findings below it as "the scan produced nothing."
    if result.returncode not in (0, None) and findings:
        result_dict["note"] = (
            f"WhatWeb exited with code {result.returncode} but stdout contained valid "
            "JSON — the findings below were successfully parsed regardless of the "
            "overall success flag."
        )
    return result_dict


def run(
    target: str = "",
    aggression: str = "1",
    verbose: bool = False,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "target": target,
        "aggression": aggression,
        "verbose": verbose,
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
