"""
TLS/SSL deep configuration scan via SSLyze — WSTG-CRYP coverage.

Unlike tlsx (which only reads SANs/issuer), SSLyze probes the actual TLS
handshake surface: supported protocol versions (SSLv2/3, TLS 1.0–1.3), accepted
cipher suites (flags RC4/3DES/NULL/EXPORT/anon), certificate deployment
(expiry, self-signed, hostname match, key size), and known TLS vulnerabilities
(Heartbleed, ROBOT, CCS injection, insecure renegotiation).

Args:
    target: host or host:port (default port 443).
    additional_args: extra sslyze flags.

Returns:
    SSLyze JSON on stdout (parsed into TLS vulnerability findings by the backend).

Category: vuln
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

TOOL_NAME = "sslyze_scan"
CATEGORY = "vuln"


def build_command(**params: Any) -> str:
    target = str(params.get("target") or params.get("host") or params.get("url") or "").strip()
    additional_args = str(params.get("additional_args", "") or "").strip()
    if not target:
        raise ValueError("sslyze_scan requires target (host or host:port)")

    # Strip scheme; default to :443 when no port given.
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.split("/", 1)[0].strip()
    if ":" not in target:
        target = f"{target}:443"

    # --json_out=- streams the machine-readable result to stdout for parsing.
    # Default scan set (protocols + ciphers + certinfo + vuln checks) runs when
    # no specific scan flags are given.
    cmd = f"sslyze --json_out=- {target}"
    if additional_args:
        cmd += f" {additional_args}"
    return cmd


def parse(result: ToolResult) -> dict[str, Any]:
    # Real extraction happens in the backend parser (parsers/vuln.parse_sslyze).
    return {"raw": bool(result.raw_stdout)}


def run(
    target: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {"target": target, "additional_args": additional_args}
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
