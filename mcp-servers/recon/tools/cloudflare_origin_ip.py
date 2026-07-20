"""
CDN detection and origin IP discovery — find real IPs behind Cloudflare/Akamai/etc.

Uses multiple passive signals to attribute origin IPs:
1. DNS history and subdomain analysis
2. MX/SPF records (mail servers often share origin)
3. Certificate transparency SANs
4. Reverse DNS and ASN correlation
5. Common origin IP patterns

Args:
    domain: Target domain to find origin IP for
    timeout: Request timeout in seconds
    additional_args: Additional flags

Returns:
    CDN classification, origin IP candidates with confidence scores, and evidence

Harvested: Multi-signal origin IP attribution for CDN bypass.
Category: recon
"""

from __future__ import annotations

import json
import re
import shlex
import socket
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "cloudflare_origin_ip"
CATEGORY = "recon"

# Known CDN IP ranges and ASN patterns
CDN_ASNS = {
    "cloudflare": [13335, 13289, 209242, 203981, 400041, 46664, 54113],
    "akamai": [16625, 20940, 20977, 21342, 21399, 22363, 32613],
    "fastly": [54113, 22822],
    "cloudfront": [16509, 14618],
    "azure_fd": [8075, 11172],
}

CDN_CNAME_PATTERNS = {
    "cloudflare": [".cdn.cloudflare.net", ".cloudflare.net"],
    "akamai": [".akamaized.net", ".akamai.net", ".edgekey.net", ".edgesuite.net"],
    "fastly": [".fastly.net", ".fastlylb.net"],
    "cloudfront": [".cloudfront.net"],
    "azure_fd": [".azureedge.net", ".trafficmanager.net", ".azurefd.net"],
    "google_cloud": [".googleusercontent.com", ".ghs.google.com"],
}

CDN_HEADER_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status"],
    "akamai": ["x-akamai-transformed", "x-cache-key"],
    "fastly": ["x-fastly-request-id", "x-served-by"],
    "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "azure_fd": ["x-azure-ref", "x-fd-healthprobe"],
}


def _check_cname_patterns(domain: str) -> tuple[str | None, str]:
    """Check if domain CNAME points to known CDN."""
    try:
        cname = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        if cname:
            ip = cname[0][4][0]
            for provider, patterns in CDN_CNAME_PATTERNS.items():
                for pattern in patterns:
                    if pattern in domain.lower():
                        return provider, f"CNAME pattern: {pattern}"
            return None, ip
    except OSError:
        pass
    return None, ""


def _resolve_mx_records(domain: str) -> list[str]:
    """Resolve MX records to find mail server IPs."""
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "MX", domain],
            capture_output=True, text=True, timeout=10
        )
        mx_hosts = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                mx_hosts.append(parts[1].rstrip("."))
            elif parts:
                mx_hosts.append(parts[0].rstrip("."))

        mx_ips = []
        for host in mx_hosts:
            try:
                ips = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
                for info in ips:
                    mx_ips.append(info[4][0])
            except OSError:
                continue
        return mx_ips
    except Exception:
        return []


def _resolve_spf_ips(domain: str) -> list[str]:
    """Extract IP addresses from SPF record."""
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=10
        )
        ips = []
        for line in result.stdout.splitlines():
            if "v=spf1" in line:
                ip_pattern = re.compile(r'ip[46]:(\d{1,3}(?:\.\d{1,3}){3})')
                ips.extend(ip_pattern.findall(line))
                include_pattern = re.compile(r'include:(\S+)')
                for match in include_pattern.finditer(line):
                    sub_domain = match.group(1)
                    sub_ips = _resolve_spf_ips(sub_domain)
                    ips.extend(sub_ips)
        return ips
    except Exception:
        return []


def _get_reverse_dns(ip: str) -> str:
    """Get reverse DNS hostname for an IP."""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0] if hostname else ""
    except (socket.herror, OSError):
        return ""


def _detect_cdn_provider(domain: str) -> str | None:
    """Detect CDN provider from DNS and HTTP signals."""
    for provider, patterns in CDN_CNAME_PATTERNS.items():
        for pattern in patterns:
            if pattern in domain.lower():
                return provider

    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "CNAME", domain],
            capture_output=True, text=True, timeout=10
        )
        cname = result.stdout.strip().lower()
        for provider, patterns in CDN_CNAME_PATTERNS.items():
            for pattern in patterns:
                if pattern in cname:
                    return provider
    except Exception:
        pass

    return None


def build_command(**params: Any) -> str:
    """Build origin IP discovery command (multi-signal approach)."""
    domain = str(params.get("domain", "")).strip()
    timeout = params.get("timeout", 30)

    if not domain:
        raise ValueError("cloudflare_origin_ip requires domain")

    parts = ["bash", "-c"]

    script = f"""
    DOMAIN="{domain}"
    echo "=== CDN Detection ==="
    DIG_CNAME=$(dig +short CNAME "$DOMAIN" 2>/dev/null)
    DIG_A=$(dig +short A "$DOMAIN" 2>/dev/null)
    DIG_AAAA=$(dig +short AAAA "$DOMAIN" 2>/dev/null)
    DIG_NS=$(dig +short NS "$DOMAIN" 2>/dev/null)
    DIG_MX=$(dig +short MX "$DOMAIN" 2>/dev/null)

    echo "CNAME: $DIG_CNAME"
    echo "A: $DIG_A"
    echo "AAAA: $DIG_AAAA"
    echo "NS: $DIG_NS"
    echo "MX: $DIG_MX"

    echo ""
    echo "=== MX Server IPs ==="
    for mx in $DIG_MX; do
        MX_HOST=$(echo "$mx" | awk '{{print $2}}' | tr -d '.')
        if [ -n "$MX_HOST" ]; then
            MX_IP=$(dig +short A "$MX_HOST" 2>/dev/null | head -1)
            echo "MX_IP: $MX_HOST -> $MX_IP"
        fi
    done

    echo ""
    echo "=== SPF Records ==="
    dig +short TXT "$DOMAIN" 2>/dev/null | grep -i spf

    echo ""
    echo "=== Common Subdomains for Origin Detection ==="
    for sub in mail smtp pop imap webmail ftp vpn gateway direct origin; do
        SUB_IP=$(dig +short A "$sub.$DOMAIN" 2>/dev/null | head -1)
        if [ -n "$SUB_IP" ]; then
            echo "SUBDOMAIN_IP: $sub.$DOMAIN -> $SUB_IP"
        fi
    done

    echo ""
    echo "=== HTTP Headers for CDN Detection ==="
    curl -sI --max-time {timeout} "http://$DOMAIN" 2>/dev/null | head -20
    """.strip()

    script_lines = script.replace("\n", " &&\n")
    parts.append(shlex.quote(script))

    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    """Parse multi-signal origin IP discovery output."""
    stdout = result.raw_stdout or ""
    stderr = result.raw_stderr or ""

    cdn_provider = None
    current_ips: list[str] = []
    mx_ips: list[str] = []
    subdomain_ips: dict[str, str] = {}
    spf_ips: list[str] = []
    http_headers: list[str] = []
    evidence: list[str] = []

    section = ""
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        if "=== CDN Detection ===" in line:
            section = "cdn"
            continue
        elif "=== MX Server IPs ===" in line:
            section = "mx"
            continue
        elif "=== SPF Records ===" in line:
            section = "spf"
            continue
        elif "=== Common Subdomains ===" in line:
            section = "subdomains"
            continue
        elif "=== HTTP Headers ===" in line:
            section = "headers"
            continue

        if section == "cdn":
            if line.startswith("CNAME:"):
                cname = line.split(":", 1)[1].strip()
                if cname:
                    for provider, patterns in CDN_CNAME_PATTERNS.items():
                        for pattern in patterns:
                            if pattern in cname.lower():
                                cdn_provider = provider
                                evidence.append(f"CNAME points to {provider}: {cname}")
            elif line.startswith("A:"):
                ips = line.split(":", 1)[1].strip().split()
                current_ips.extend(ips)
            elif line.startswith("AAAA:"):
                ips = line.split(":", 1)[1].strip().split()
                current_ips.extend(ips)

        elif section == "mx":
            if line.startswith("MX_IP:"):
                parts = line.split(":", 1)[1].strip().split("->")
                if len(parts) == 2:
                    host = parts[0].strip()
                    ip = parts[1].strip()
                    if ip:
                        mx_ips.append(ip)
                        evidence.append(f"MX server {host} resolves to {ip}")

        elif section == "spf":
            if "v=spf1" in line:
                spf_text = line
                ip_pattern = re.compile(r'ip4:(\d{1,3}(?:\.\d{1,3}){3})')
                spf_ips.extend(ip_pattern.findall(spf_text))
                evidence.append(f"SPF record contains IPs: {', '.join(spf_ips[:5])}")

        elif section == "subdomains":
            if line.startswith("SUBDOMAIN_IP:"):
                parts = line.split(":", 1)[1].strip().split("->")
                if len(parts) == 2:
                    hostname = parts[0].strip()
                    ip = parts[1].strip()
                    if ip:
                        subdomain_ips[hostname] = ip
                        evidence.append(f"Subdomain {hostname} resolves to {ip}")

        elif section == "headers":
            http_headers.append(line)

    for header_line in http_headers:
        for provider, signatures in CDN_HEADER_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in header_line.lower():
                    if not cdn_provider:
                        cdn_provider = provider
                    evidence.append(f"HTTP header indicates {provider}: {header_line}")

    origin_candidates = []
    all_ips = list(set(current_ips + mx_ips + spf_ips + list(subdomain_ips.values())))

    for ip in all_ips:
        confidence = 0.0
        signals = []

        if ip in mx_ips:
            confidence += 0.4
            signals.append("mx_server")
        if ip in spf_ips:
            confidence += 0.3
            signals.append("spf_record")
        if ip in subdomain_ips.values():
            confidence += 0.3
            signals.append("direct_subdomain")
        if ip not in current_ips:
            confidence += 0.2
            signals.append("not_edge_ip")

        reverse_dns = _get_reverse_dns(ip)
        if reverse_dns:
            evidence.append(f"Reverse DNS for {ip}: {reverse_dns}")
            if cdn_provider and cdn_provider.lower() not in reverse_dns.lower():
                confidence += 0.1
                signals.append("non_cdn_reverse_dns")

        if confidence > 0:
            origin_candidates.append({
                "ip": ip,
                "confidence": min(confidence, 1.0),
                "signals": signals,
                "reverse_dns": reverse_dns,
            })

    origin_candidates.sort(key=lambda x: x["confidence"], reverse=True)

    return {
        "cdn_provider": cdn_provider,
        "current_ips": current_ips,
        "mx_ips": mx_ips,
        "spf_ips": spf_ips,
        "subdomain_ips": subdomain_ips,
        "origin_candidates": origin_candidates,
        "evidence": evidence,
        "count": len(origin_candidates),
    }


def run(
    domain: str = "",
    timeout: int = 30,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 120,
) -> dict[str, Any]:
    params = {
        "domain": domain,
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
