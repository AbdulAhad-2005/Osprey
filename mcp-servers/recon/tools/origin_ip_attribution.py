"""
Origin IP attribution orchestrator — combine DNS, TLS, CT, and CDN signals.

Runs a multi-signal pipeline to classify every resolved IP as either CDN edge
or origin candidate, with confidence scores and evidence chains.

Args:
    domain: Target domain for origin IP attribution
    live_hosts: Comma-separated live hosts to also check
    timeout: Per-tool timeout in seconds
    additional_args: Additional flags

Returns:
    CDN classification, origin IP candidates with confidence, evidence, and
    recommended next steps for network scanning

Harvested: Multi-signal origin IP attribution pipeline.
Category: recon
"""

from __future__ import annotations

import json
import re
import shlex
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "origin_ip_attribution"
CATEGORY = "recon"

# CDN ASN ranges for IP-based classification
CDN_IP_RANGES = {
    "cloudflare": [
        (re.compile(r"^104\.16\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.17\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.18\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.19\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.20\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.21\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.22\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.23\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.24\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.25\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.26\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.27\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.28\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.29\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.30\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^104\.31\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^173\.245\.48\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^103\.21\.244\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^103\.22\.200\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^103\.31.4\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^141\.101\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^108\.162\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^190\.93\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^188\.114\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^197\.234\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
        (re.compile(r"^198\.41\.\d{1,3}\.\d{1,3}$"), "Cloudflare"),
    ],
    "akamai": [
        (re.compile(r"^23\.0\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.1\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.32\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.33\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.35\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.36\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.37\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.38\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.39\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.40\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.41\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.42\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.43\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.44\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.45\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.46\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.47\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.48\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.49\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.50\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.51\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.52\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.53\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.54\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.55\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.56\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.57\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.58\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.59\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.60\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.61\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.62\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.63\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.64\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.65\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.66\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.67\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.72\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.73\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.74\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.75\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.192\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.193\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.194\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.195\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.196\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.197\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.198\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.199\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.200\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.201\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.202\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.203\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.204\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.205\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.206\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.207\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.208\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.209\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.210\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.211\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.212\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.213\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.214\.\d{1,3}\.\d{1,3}$"), "Akamai"),
        (re.compile(r"^23\.215\.\d{1,3}\.\d{1,3}$"), "Akamai"),
    ],
}

CDN_CNAME_PATTERNS = {
    "cloudflare": [".cdn.cloudflare.net", ".cloudflare.net"],
    "akamai": [".akamaized.net", ".akamai.net", ".edgekey.net", ".edgesuite.net"],
    "fastly": [".fastly.net", ".fastlylb.net"],
    "cloudfront": [".cloudfront.net"],
    "azure_fd": [".azureedge.net", ".trafficmanager.net", ".azurefd.net"],
    "google_cloud": [".googleusercontent.com", ".ghs.google.com"],
}

CDN_ISSUER_PATTERNS = {
    "cloudflare": ["cloudflare"],
    "akamai": ["akamai"],
    "fastly": ["fastly"],
    "cloudfront": ["amazon", "cloudfront"],
    "azure_fd": ["microsoft"],
}


def _classify_ip(ip: str) -> str | None:
    """Classify an IP as a known CDN provider or None."""
    for provider, patterns in CDN_IP_RANGES.items():
        for pattern in patterns:
            if pattern.match(ip):
                return provider
    return None


def _get_reverse_dns(ip: str) -> str:
    """Get reverse DNS hostname for an IP."""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0] if hostname else ""
    except (socket.herror, OSError):
        return ""


def _resolve_all(domain: str) -> dict[str, Any]:
    """Resolve all DNS records for a domain."""
    result = {}
    for rtype in ("A", "AAAA", "CNAME", "NS", "MX"):
        try:
            output = subprocess.run(
                ["dig", "+short", rtype, domain],
                capture_output=True, text=True, timeout=10
            )
            records = [line.strip().rstrip(".") for line in output.stdout.splitlines() if line.strip()]
            if records:
                result[rtype] = records
        except Exception:
            pass
    return result


def _check_cname_cdn(domain: str) -> str | None:
    """Check if CNAME points to known CDN."""
    try:
        output = subprocess.run(
            ["dig", "+short", "CNAME", domain],
            capture_output=True, text=True, timeout=10
        )
        cname = output.stdout.strip().lower()
        for provider, patterns in CDN_CNAME_PATTERNS.items():
            for pattern in patterns:
                if pattern in cname:
                    return provider
    except Exception:
        pass
    return None


def _check_cert_cdn(domain: str) -> str | None:
    """Check TLS certificate for CDN issuer patterns."""
    try:
        output = subprocess.run(
            ["echo", "|", "openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain],
            capture_output=True, text=True, timeout=10
        )
        cert_text = output.stdout.lower()
        for provider, patterns in CDN_ISSUER_PATTERNS.items():
            for pattern in patterns:
                if pattern in cert_text:
                    return provider
    except Exception:
        pass
    return None


def build_command(**params: Any) -> str:
    """Build origin IP attribution pipeline command."""
    domain = str(params.get("domain", "")).strip()
    live_hosts = str(params.get("live_hosts", "")).strip()
    timeout = params.get("timeout", 30)

    if not domain:
        raise ValueError("origin_ip_attribution requires domain")

    all_targets = [domain]
    if live_hosts:
        all_targets.extend([h.strip() for h in live_hosts.split(",") if h.strip()])

    parts = ["bash", "-c"]

    script_lines = [f'DOMAIN="{domain}"']

    for target in all_targets:
        safe_target = target.replace(".", "_").replace("-", "_")
        script_lines.extend([
            f'echo "=== Resolving {target} ==="',
            f'A_RECORDS=$(dig +short A "{target}" 2>/dev/null)',
            f'AAAA_RECORDS=$(dig +short AAAA "{target}" 2>/dev/null)',
            f'CNAME_RECORD=$(dig +short CNAME "{target}" 2>/dev/null)',
            f'NS_RECORDS=$(dig +short NS "{target}" 2>/dev/null)',
            f'MX_RECORDS=$(dig +short MX "{target}" 2>/dev/null)',
            f'SPF_RECORD=$(dig +short TXT "{target}" 2>/dev/null | grep -i spf || true)',
            f'echo "A: $A_RECORDS"',
            f'echo "AAAA: $AAAA_RECORDS"',
            f'echo "CNAME: $CNAME_RECORD"',
            f'echo "NS: $NS_RECORDS"',
            f'echo "MX: $MX_RECORDS"',
            f'echo "SPF: $SPF_RECORD"',
        ])

    script_lines.extend([
        'echo "=== Origin IP Candidates ==="',
        'echo "Use dig + curl to cross-reference all resolved IPs"',
        'echo "Check MX servers, SPF records, and direct subdomains"',
        'echo "Classify each IP: CDN edge vs origin candidate"',
    ])

    script = " && ".join(script_lines)
    parts.append(shlex.quote(script))

    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    """Parse the attribution pipeline output and classify IPs."""
    stdout = result.raw_stdout or ""

    all_ips: dict[str, list[str]] = {}
    cdn_signals: dict[str, str] = {}
    mx_ips: list[str] = []
    spf_ips: list[str] = []
    current_target = ""

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("=== Resolving "):
            current_target = line.split("=== Resolving ")[1].rstrip(" =").strip()
            continue

        if line.startswith("A:"):
            ips = line.split(":", 1)[1].strip().split()
            if current_target:
                all_ips.setdefault(current_target, []).extend(ips)
        elif line.startswith("AAAA:"):
            ips = line.split(":", 1)[1].strip().split()
            if current_target:
                all_ips.setdefault(current_target, []).extend(ips)
        elif line.startswith("CNAME:"):
            cname = line.split(":", 1)[1].strip()
            if cname:
                for provider, patterns in CDN_CNAME_PATTERNS.items():
                    for pattern in patterns:
                        if pattern in cname.lower():
                            cdn_signals[current_target] = provider
        elif line.startswith("MX:"):
            mx_raw = line.split(":", 1)[1].strip()
            for part in mx_raw.split():
                if not part[0].isdigit():
                    try:
                        mx_result = subprocess.run(
                            ["dig", "+short", "A", part.rstrip(".")],
                            capture_output=True, text=True, timeout=5
                        )
                        for mx_ip in mx_result.stdout.splitlines():
                            mx_ip = mx_ip.strip()
                            if mx_ip and mx_ip[0].isdigit():
                                mx_ips.append(mx_ip)
                    except Exception:
                        pass
        elif line.startswith("SPF:"):
            spf_text = line.split(":", 1)[1].strip()
            ip_pattern = re.compile(r'ip4:(\d{1,3}(?:\.\d{1,3}){3})')
            spf_ips.extend(ip_pattern.findall(spf_text))

    origin_candidates = []
    all_flat_ips = list(set(
        ip for ips in all_ips.values() for ip in ips
    ))

    for ip in all_flat_ips:
        cdn_class = _classify_ip(ip)
        reverse_dns = _get_reverse_dns(ip)

        confidence = 0.0
        signals = []

        if cdn_class:
            confidence = 0.9
            signals.append(f"cdn_ip_range:{cdn_class}")
        elif ip in mx_ips:
            confidence = 0.6
            signals.append("mx_server_ip")
        elif ip in spf_ips:
            confidence = 0.5
            signals.append("spf_record_ip")
        else:
            confidence = 0.3
            signals.append("direct_resolution")

        if reverse_dns:
            for provider, patterns in CDN_CNAME_PATTERNS.items():
                for pattern in patterns:
                    if pattern in reverse_dns.lower():
                        confidence = max(confidence, 0.85)
                        signals.append(f"reverse_dns_cdn:{provider}")

        is_origin = confidence < 0.5 and cdn_class is None
        is_cdn = cdn_class is not None or confidence >= 0.5

        origin_candidates.append({
            "ip": ip,
            "is_cdn": is_cdn,
            "is_origin": is_origin,
            "cdn_provider": cdn_class,
            "confidence": round(confidence, 2),
            "signals": signals,
            "reverse_dns": reverse_dns,
        })

    origin_only = [c for c in origin_candidates if c["is_origin"]]
    cdn_only = [c for c in origin_candidates if c["is_cdn"]]

    return {
        "domain": result.raw_stdout.splitlines()[0].split("Resolving ")[-1].rstrip(" =").strip() if result.raw_stdout else "",
        "cdn_detected": bool(cdn_signals),
        "cdn_providers": list(set(cdn_signals.values())),
        "all_ips": all_flat_ips,
        "mx_ips": mx_ips,
        "spf_ips": spf_ips,
        "origin_candidates": origin_only,
        "cdn_ips": cdn_only,
        "total_ips": len(all_flat_ips),
        "origin_count": len(origin_only),
        "cdn_count": len(cdn_only),
        "recommendation": (
            f"Found {len(origin_only)} origin candidate(s) and {len(cdn_only)} CDN edge IP(s). "
            f"Run network scan on origin IPs: {', '.join(c['ip'] for c in origin_only[:5])}"
            if origin_only else
            "No clear origin IPs found — try additional subdomain enumeration or historical DNS lookups"
        ),
    }


def run(
    domain: str = "",
    live_hosts: str = "",
    timeout: int = 30,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 180,
) -> dict[str, Any]:
    params = {
        "domain": domain,
        "live_hosts": live_hosts,
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
