"""
TLS certificate inspection with tlsx — extract SANs, issuer, expiry, and origin clues.

Args:
    targets: Hostnames or IPs to inspect (newline-separated or single)
    target_file: File containing targets
    port: TLS port to connect to (default: 443)
    protocol: TLS protocol version (tls10, tls11, tls12, tls13)
    timeout: Connection timeout in seconds
    additional_args: Additional tlsx arguments

Returns:
    TLS certificate details including SANs, issuer, subject, serial, and expiry

Harvested: ProjectDiscovery tlsx for TLS certificate intelligence.
Category: recon
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

TOOL_NAME = "tlsx_inspect"
CATEGORY = "recon"

# Known CDN/provider certificate patterns for origin detection
CDN_ISSUER_PATTERNS = {
    "cloudflare": ["cloudflare"],
    "akamai": ["akamai", "akamaized", "edgekey"],
    "fastly": ["fastly"],
    "cloudfront": ["cloudfront", "amazon"],
    "azure_fd": ["azure"],
}


def build_command(**params: Any) -> str:
    """Build tlsx CLI command for TLS certificate inspection."""
    target = str(params.get("target", "")).strip()
    target_file = str(params.get("target_file", "")).strip()
    port = params.get("port", 443)
    protocol = str(params.get("protocol", "")).strip()
    timeout = params.get("timeout", 5)
    additional_args = str(params.get("additional_args", "")).strip()

    parts = ["tlsx", "-silent", "-json"]

    if port:
        parts.append(f"-port {port}")

    if protocol:
        proto_map = {"tls10": "-tls-version tls10", "tls11": "-tls-version tls11",
                     "tls12": "-tls-version tls12", "tls13": "-tls-version tls13"}
        if protocol.lower() in proto_map:
            parts.append(proto_map[protocol.lower()])

    if timeout:
        parts.append(f"-timeout {timeout}")

    if additional_args:
        parts.append(additional_args)

    if target_file and Path(target_file).is_file():
        parts.append(f"-l {shlex.quote(target_file)}")
    elif target:
        lines = [line.strip() for line in target.replace(",", "\n").splitlines() if line.strip()]
        if len(lines) == 1:
            parts.append(f"-host {shlex.quote(lines[0])}")
        else:
            quoted = " ".join(shlex.quote(line) for line in lines)
            parts.append(f"-host {quoted}")
    else:
        raise ValueError("tlsx_inspect requires target or target_file")

    return " ".join(parts)


def _detect_cdn_from_cert(cert_info: dict[str, Any]) -> str | None:
    """Detect CDN provider from certificate issuer/subject patterns."""
    issuer = str(cert_info.get("issuer", "")).lower()
    subject = str(cert_info.get("subject", "")).lower()
    sans = [str(s).lower() for s in cert_info.get("sans", [])]

    for provider, patterns in CDN_ISSUER_PATTERNS.items():
        for pattern in patterns:
            if pattern in issuer or pattern in subject:
                return provider
            for san in sans:
                if pattern in san:
                    return provider
    return None


def parse(result: ToolResult) -> dict[str, Any]:
    """Parse tlsx JSON output into structured TLS certificate data."""
    findings = []
    stdout = result.raw_stdout or ""

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            import json
            cert = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        host = cert.get("host", "")
        ip = cert.get("ip", "")
        port = cert.get("port", 443)
        probe_ok = cert.get("probe_status", False)
        tls_version = cert.get("tls_version", "")
        cipher = cert.get("cipher", "")
        san = cert.get("subject_an", [])
        if isinstance(san, str):
            san = [s.strip() for s in san.split(",")]

        issuer_dn = cert.get("issuer_dn", "")
        issuer_cn = cert.get("issuer_cn", "")
        issuer_org = cert.get("issuer_org", [])
        issuer_org_str = ", ".join(issuer_org) if isinstance(issuer_org, list) else str(issuer_org)
        subject_dn = cert.get("subject_dn", "")
        subject_cn = cert.get("subject_cn", "")
        serial = cert.get("serial", "")
        not_before = cert.get("not_before", "")
        not_after = cert.get("not_after", "")
        fingerprint = cert.get("fingerprint_hash", {}).get("sha256", "")

        cdn_provider = _detect_cdn_from_cert({
            "issuer": f"{issuer_dn} {issuer_cn} {issuer_org_str}",
            "subject": f"{subject_dn} {subject_cn}",
            "sans": san,
        })

        findings.append({
            "host": host,
            "ip": ip,
            "port": port,
            "probe_status": probe_ok,
            "tls_version": tls_version,
            "cipher": cipher,
            "sans": san,
            "issuer": issuer_dn,
            "issuer_cn": issuer_cn,
            "issuer_org": issuer_org,
            "subject": subject_dn,
            "subject_cn": subject_cn,
            "serial": serial,
            "not_before": not_before,
            "not_after": not_after,
            "fingerprint": fingerprint,
            "cdn_provider": cdn_provider,
            "is_cdn_cert": cdn_provider is not None,
        })

    return {"tls_certificates": findings, "count": len(findings)}


def run(
    target: str = "",
    target_file: str = "",
    port: int = 443,
    protocol: str = "",
    timeout: int = 5,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "target": target,
        "target_file": target_file,
        "port": port,
        "protocol": protocol,
        "timeout": timeout,
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
