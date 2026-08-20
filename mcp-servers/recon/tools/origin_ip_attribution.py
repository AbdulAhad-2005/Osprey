"""
Origin IP attribution orchestrator — combine DNS, TLS, CT, and CDN signals.

Runs a multi-signal pipeline to classify every resolved IP as either CDN edge
or origin candidate, with confidence scores and evidence chains.

Phase 0: Confirm CDN presence, pull CDN IP ranges as denylist
Phase 1: Passive DNS resolution (A/AAAA/CNAME/NS/MX/TXT), CNAME pattern matching
Phase 2: MX-to-IP resolution, SPF IP extraction, subdomain probing
Phase 3: HTTP header CDN signature detection, TLS cert issuer analysis
Phase 4: IP classification against CDN denylist, origin candidate scoring
Phase 5: Verification — direct IP + Host header check for top candidates

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

import ipaddress
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
from _core.command_utils import q

TOOL_NAME = "origin_ip_attribution"
CATEGORY = "recon"

# ---------------------------------------------------------------------------
# CDN IP ranges — sourced from each provider's published CIDR lists.
# Use ipaddress.ip_network() for proper matching instead of regex enumeration.
# Updated 2025-07; re-check periodically.
# ---------------------------------------------------------------------------

CDN_CIDRS: dict[str, list[str]] = {
    "cloudflare": [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    ],
    "akamai": [
        "23.0.0.0/12",
        "23.32.0.0/11",
        "23.64.0.0/14",
        "23.72.0.0/13",
        "23.192.0.0/11",
        "104.64.0.0/10",
        "184.24.0.0/13",
        "184.50.0.0/15",
        "184.84.0.0/14",
        "2.16.0.0/13",
        "2.18.0.0/15",
        "2.20.0.0/14",
        "2.22.0.0/15",
        "2.128.0.0/13",
        "2.160.0.0/11",
        "96.0.0.0/11",
        "96.16.0.0/15",
        "96.24.0.0/14",
        "104.64.0.0/10",
    ],
    "fastly": [
        "151.101.0.0/16",
        "151.101.128.0/17",
        "151.101.64.0/18",
        "151.101.192.0/18",
    ],
    "cloudfront": [
        "3.160.0.0/14",
        "13.32.0.0/15",
        "13.35.0.0/16",
        "13.224.0.0/14",
        "52.84.0.0/15",
        "54.182.0.0/16",
        "54.192.0.0/12",
        "54.230.0.0/16",
        "54.239.128.0/18",
        "54.239.192.0/19",
        "54.240.128.0/18",
        "99.84.0.0/16",
        "99.86.0.0/16",
        "143.204.0.0/16",
        "204.246.164.0/22",
        "204.246.168.0/22",
        "205.251.200.0/21",
    ],
    "azure_fd": [
        "13.107.246.0/24",
        "20.200.245.0/24",
        "20.205.243.0/24",
        "40.90.0.0/16",
        "147.243.0.0/16",
    ],
    "google_cloud": [
        "130.211.0.0/22",
        "130.211.4.0/24",
        "130.211.8.0/21",
        "130.211.16.0/20",
        "130.211.32.0/19",
        "130.211.64.0/18",
        "130.211.128.0/17",
        "34.64.0.0/10",
        "34.128.0.0/10",
        "35.184.0.0/13",
        "35.192.0.0/14",
        "35.196.0.0/15",
        "35.224.0.0/12",
        "35.240.0.0/13",
        "35.200.0.0/13",
        "34.2.0.0/15",
    ],
    "incapsula": [
        "45.60.0.0/15",
        "45.64.0.0/14",
        "103.28.248.0/22",
        "199.83.128.0/21",
        "198.143.32.0/19",
        "149.126.72.0/21",
        "45.60.0.0/16",
    ],
}

# Pre-compute ip_network objects for fast lookup
_CDN_NETWORKS: dict[str, list[ipaddress.IPv4Network]] = {}
for _provider, _cidrs in CDN_CIDRS.items():
    _CDN_NETWORKS[_provider] = [ipaddress.ip_network(c, strict=False) for c in _cidrs]


CDN_CNAME_PATTERNS = {
    "cloudflare": [".cdn.cloudflare.net", ".cloudflare.net"],
    "akamai": [".akamaized.net", ".akamai.net", ".edgekey.net", ".edgesuite.net"],
    "fastly": [".fastly.net", ".fastlylb.net"],
    "cloudfront": [".cloudfront.net"],
    "azure_fd": [".azureedge.net", ".trafficmanager.net", ".azurefd.net"],
    "google_cloud": [".googleusercontent.com", ".ghs.google.com"],
    "incapsula": [".incapsula.com", ".imperva.com"],
    "stackpath": [".stackpathcdn.com"],
    "keycdn": [".kxcdn.com"],
    "cachefly": [".cachefly.net"],
}

CDN_HEADER_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "cf-connecting-ip"],
    "akamai": ["x-akamai-transformed", "x-cache-key", "x-true-cache-key"],
    "fastly": ["x-fastly-request-id", "x-served-by", "x-cache", "x-s", "x-timer"],
    "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "azure_fd": ["x-azure-ref", "x-fd-healthprobe"],
    "google_cloud": ["x-cloud-trace-context"],
    "incapsula": ["x-iinfo", "x-cdn", "incapsula"],
    "stackpath": ["x-stackpath"],
}

# TLS certificate issuer patterns — only match CDN-specific issuers, not CAs
CDN_CERT_ISSUERS = {
    "cloudflare": ["cloudflare"],
    "akamai": ["akamai", "akamaized", "edgekey"],
    "fastly": ["fastly"],
    "cloudfront": ["cloudfront"],  # NOT "amazon" — that's the CA
    "azure_fd": ["azure front door"],  # NOT just "azure" — too broad
}

# Subdomains disproportionately likely to bypass CDN
ORIGIN_SUBDOMAINS = [
    "mail", "smtp", "pop", "imap", "webmail", "ftp", "vpn", "gateway",
    "direct", "origin", "owa", "autodiscover", "dev", "staging", "test",
    "admin", "internal", "api", "portal", "git", "wiki", "docs", "forum",
    "support", "cdn", "static", "assets", "img", "media", "db", "mysql",
    "redis", "ns1", "ns2", "ns3", "remote", "ssh", "jenkins", "jira",
    "confluence", "gitlab", "svn", "ldap", "radius", "sip", "rtp",
    "xmpp", "caldav", "carddav", "exchange", "dns", "ntp", "syslog",
    "backup", "monitor", "grafana", "prometheus", "kibana", "elastic",
    "splunk", "nagios", "zabbix", "cacti", "munin", "puppet", "chef",
    "ansible", "salt", "k8s", "kubernetes", "docker", "registry",
]


def _classify_ip(ip_str: str) -> str | None:
    """Classify an IP against published CDN CIDR ranges. Returns provider or None."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for provider, networks in _CDN_NETWORKS.items():
        for net in networks:
            if addr in net:
                return provider
    return None


def _get_reverse_dns(ip: str) -> str:
    """Get reverse DNS hostname for an IP."""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0] if hostname else ""
    except (socket.herror, OSError):
        return ""


def _check_cert_cdn(domain: str) -> str | None:
    """Check TLS certificate issuer for CDN patterns via openssl."""
    try:
        cmd = f"echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | grep -i 'issuer\\|subject\\|o ='"
        output = subprocess.run(
            ["bash", "-c", cmd],
            capture_output=True, text=True, timeout=10,
        )
        cert_text = output.stdout.lower()
        if not cert_text:
            return None
        for provider, patterns in CDN_CERT_ISSUERS.items():
            for pattern in patterns:
                if pattern in cert_text:
                    return provider
    except Exception:
        pass
    return None


def _verify_origin_candidate(ip: str, domain: str, timeout: int = 10) -> dict[str, Any]:
    """Verify if a candidate IP actually serves the target domain."""
    evidence: list[str] = []
    is_verified = False
    cert_match = False

    # Direct request with Host header
    for scheme in ("https", "http"):
        try:
            cmd = f"curl -s{'' if scheme == 'http' else 'k'}I --max-time {timeout} -H 'Host: {domain}' {scheme}://{ip}/"
            output = subprocess.run(
                ["bash", "-c", cmd],
                capture_output=True, text=True, timeout=timeout + 5,
            )
            headers = output.stdout
            if not headers:
                continue

            # Check if response looks like the target (not default/parking page)
            headers_lower = headers.lower()
            status_line = headers.splitlines()[0] if headers.splitlines() else ""
            if "200" in status_line or "301" in status_line or "302" in status_line:
                is_verified = True
                evidence.append(f"Direct {scheme} to {ip} returns: {status_line.strip()}")

            # Check for CDN headers (should be ABSENT on origin)
            for provider, sigs in CDN_HEADER_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in headers_lower:
                        evidence.append(f"CDN header {sig} present on direct IP — may still be behind CDN")
                        is_verified = False
                        break
        except Exception:
            continue

    # Compare TLS cert with what CDN serves
    try:
        cmd = f"echo | openssl s_client -connect {ip}:443 -servername {domain} 2>/dev/null | openssl x509 -noout -subject -issuer 2>/dev/null"
        output = subprocess.run(
            ["bash", "-c", cmd],
            capture_output=True, text=True, timeout=10,
        )
        cert_info = output.stdout.strip()
        if cert_info:
            evidence.append(f"Cert on direct IP: {cert_info}")
            # Check if cert matches domain
            if domain in cert_info or f"CN = {domain}" in cert_info:
                cert_match = True
                evidence.append("Cert CN/SAN matches target domain")
    except Exception:
        pass

    return {
        "is_verified": is_verified,
        "cert_match": cert_match,
        "evidence": evidence,
    }


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

    script_lines = ["set -e", f'DOMAIN={q(domain)}', f'TIMEOUT={timeout}']

    for target in all_targets:
        script_lines.extend([
            f'echo "=== Resolving "{q(target)}" ==="',
            # Use dig for CNAME+full output, also host for clean A resolution.
            # dig/host print one value per line for a multi-A-record domain —
            # `paste -sd" " -` folds each into a single space-joined line
            # before it's echoed, so the "A:"/"A_HOSTS:"/"AAAA:" line-prefix
            # parsing in parse() below actually sees every value instead of
            # only the first line (a second/third A record with no prefix
            # was previously invisible to the section parser).
            f'A_RECORDS=$(dig +short A {q(target)} 2>/dev/null | paste -sd" " -)',
            f'A_HOSTS=$(host -t A {q(target)} 2>/dev/null | grep "has address" | awk \'{{print $NF}}\' | sort -u | paste -sd" " -)',
            f'AAAA_RECORDS=$(dig +short AAAA {q(target)} 2>/dev/null | paste -sd" " -)',
            f'CNAME_RECORD=$(dig +short CNAME {q(target)} 2>/dev/null)',
            f'NS_RECORDS=$(dig +short NS {q(target)} 2>/dev/null)',
            f'MX_RECORDS=$(dig +short MX {q(target)} 2>/dev/null)',
            f'SPF_RECORD=$(dig +short TXT {q(target)} 2>/dev/null | grep -i spf | paste -sd" " -)',
            f'echo "A: $A_RECORDS"',
            f'echo "A_HOSTS: $A_HOSTS"',
            f'echo "AAAA: $AAAA_RECORDS"',
            f'echo "CNAME: $CNAME_RECORD"',
            f'echo "NS: $NS_RECORDS"',
            f'echo "MX: $MX_RECORDS"',
            f'echo "SPF: $SPF_RECORD"',
        ])

        # Resolve MX records to IPs
        # MX format: "10 mail.example.com." — extract 2nd field as hostname
        script_lines.extend([
            f'echo "=== MX_IPS ==="',
            f'for mx_host in $(echo "$MX_RECORDS" | awk \'{{print $2}}\' | sed \'s/\\.$//\' | sort -u); do',
            f'  if [ -n "$mx_host" ] && ! echo "$mx_host" | grep -qE "^[0-9]+$"; then',
            f'    MX_IP=$(dig +short A "$mx_host" 2>/dev/null | head -1)',
            f'    if [ -n "$MX_IP" ]; then',
            f'      echo "MX_IP: $mx_host -> $MX_IP"',
            f'    fi',
            f'  fi',
            f'done',
        ])

        # Probe common subdomains (kept in sync with ORIGIN_SUBDOMAINS Python list)
        sub_list = " ".join(ORIGIN_SUBDOMAINS)
        script_lines.extend([
            f'echo "=== SUBDOMAIN_IPS ==="',
            f'for sub in {sub_list}; do',
            f'  SUB_RAW=$(dig +short A "$sub."{q(target)} 2>/dev/null | tail -1)',
            f'  SUB_IP=""',
            f'  if [ -n "$SUB_RAW" ] && echo "$SUB_RAW" | grep -qE \'^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$\'; then',
            f'    SUB_IP="$SUB_RAW"',
            f'  elif [ -n "$SUB_RAW" ]; then',
            f'    CNAME=$(echo "$SUB_RAW" | sed \'s/\\.$//\')',
            f'    SUB_IP=$(dig +short A "$CNAME" 2>/dev/null | grep -m1 -E \'^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$\' || true)',
            f'  fi',
            f'  if [ -n "$SUB_IP" ]; then',
            f'    echo "SUBDOMAIN_IP: $sub."{q(target)}" -> $SUB_IP"',
            f'  fi',
            f'done',
        ])

        # HTTP headers for CDN detection
        script_lines.extend([
            f'echo "=== HTTP_HEADERS ==="',
            f'curl -sI --max-time {timeout} "https://"{q(target)} 2>/dev/null | head -25 || true',
            f'curl -sI --max-time {timeout} "http://"{q(target)} 2>/dev/null | head -15 || true',
        ])

    script_lines.extend([
        'echo "=== DONE ==="',
    ])

    # Use \n separator (not &&) because script_lines include loops and
    # conditionals (for/do/if/then/fi/done) that break with &&-chaining.
    script = "\n".join(script_lines)
    return script


def parse(result: ToolResult) -> dict[str, Any]:
    """Parse the attribution pipeline output and classify IPs."""
    stdout = result.raw_stdout or ""

    all_ips: dict[str, list[str]] = {}
    cdn_signals: dict[str, str] = {}
    mx_ips: list[str] = []
    spf_ips: list[str] = []
    subdomain_ips: dict[str, str] = {}
    http_headers: list[str] = []
    current_target = ""

    section = ""
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Section markers
        if line.startswith("=== Resolving "):
            current_target = line.split("=== Resolving ")[1].rstrip(" =").strip()
            section = "dns"
            continue
        elif "=== MX_IPS ===" in line:
            section = "mx_ips"
            continue
        elif "=== SUBDOMAIN_IPS ===" in line:
            section = "subdomains"
            continue
        elif "=== HTTP_HEADERS ===" in line:
            section = "headers"
            continue
        elif "=== DONE ===" in line:
            section = ""
            continue

        if section == "dns":
            if line.startswith("A:"):
                ips = [ip.strip() for ip in line.split(":", 1)[1].strip().split() if ip.strip()]
                if current_target:
                    all_ips.setdefault(current_target, []).extend(ips)
            elif line.startswith("A_HOSTS:"):
                # host command output — properly resolved IPs through CNAME chains
                ips = [ip.strip() for ip in line.split(":", 1)[1].strip().split() if ip.strip()]
                for ip in ips:
                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip) and current_target:
                        all_ips.setdefault(current_target, []).append(ip)
            elif line.startswith("AAAA:"):
                ips = [ip.strip() for ip in line.split(":", 1)[1].strip().split() if ip.strip()]
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
                # Just collect raw MX text for evidence; actual IPs resolved separately
                pass
            elif line.startswith("SPF:"):
                spf_text = line.split(":", 1)[1].strip()
                ip_pattern = re.compile(r"ip4:(\d{1,3}(?:\.\d{1,3}){3})")
                spf_ips.extend(ip_pattern.findall(spf_text))

        elif section == "mx_ips":
            if line.startswith("MX_IP:"):
                parts = line.split(":", 1)[1].strip().split("->")
                if len(parts) == 2:
                    ip = parts[1].strip()
                    if ip and ip[0].isdigit() and ip not in mx_ips:
                        mx_ips.append(ip)

        elif section == "subdomains":
            if line.startswith("SUBDOMAIN_IP:"):
                parts = line.split(":", 1)[1].strip().split("->")
                if len(parts) == 2:
                    hostname = parts[0].strip()
                    ip = parts[1].strip()
                    if ip and ip[0].isdigit():
                        subdomain_ips[hostname] = ip

        elif section == "headers":
            http_headers.append(line)

    # --- Phase 3: Detect CDN from HTTP headers ---
    header_cdn = None
    for header_line in http_headers:
        for provider, signatures in CDN_HEADER_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in header_line.lower():
                    header_cdn = provider
                    break
            if header_cdn:
                break
        if header_cdn:
            break

    # Merge all CDN signals
    cdn_providers = set(cdn_signals.values())
    if header_cdn:
        cdn_providers.add(header_cdn)

    # --- Phase 3b: Detect CDN from TLS certificate issuer ---
    if not cdn_providers and current_target:
        cert_cdn = _check_cert_cdn(current_target)
        if cert_cdn:
            cdn_providers.add(cert_cdn)

    # --- Phase 4: Classify each IP ---
    origin_candidates = []
    all_flat_ips = list(set(
        ip for ips in all_ips.values() for ip in ips
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip)
    ))

    for ip in all_flat_ips:
        cdn_class = _classify_ip(ip)
        reverse_dns = _get_reverse_dns(ip)

        confidence = 0.0
        signals: list[str] = []

        # CDN IP range match — strong signal this is an edge IP
        if cdn_class:
            confidence = 0.9
            signals.append(f"cdn_ip_range:{cdn_class}")

        # Reverse DNS CDN check
        if reverse_dns:
            for provider, patterns in CDN_CNAME_PATTERNS.items():
                for pattern in patterns:
                    if pattern in reverse_dns.lower():
                        cdn_class = cdn_class or provider
                        confidence = max(confidence, 0.85)
                        signals.append(f"reverse_dns_cdn:{provider}")

        # MX server IPs — likely origin infrastructure
        if ip in mx_ips:
            confidence = max(confidence, 0.6)
            signals.append("mx_server_ip")

        # SPF record IPs — authorized sending infra
        if ip in spf_ips:
            confidence = max(confidence, 0.5)
            signals.append("spf_record_ip")

        # Direct subdomain resolution — infrastructure bypassing CDN
        if ip in subdomain_ips.values():
            confidence = max(confidence, 0.5)
            signals.append("direct_subdomain")

        # Apex domain direct IP (no CDN detected or known origin)
        is_apex_ip = ip in all_ips.get(current_target, [])
        if not cdn_providers and is_apex_ip and not signals:
            # No CDN detected — apex IP IS the origin
            confidence = 0.7
            signals.append("apex_no_cdn")

        # CDN detected but apex IP not in CDN ranges — DNS not fully proxied
        if cdn_providers and is_apex_ip and cdn_class is None and not signals:
            confidence = 0.65
            signals.append("cdn_bypass_apex_ip")

        # If not edge IP and not matching any signal
        if not is_apex_ip and not signals and cdn_class is None:
            confidence = 0.2
            signals.append("external_ip")

        is_cdn = cdn_class is not None
        is_origin = (
            not is_cdn and (
                (not cdn_providers and is_apex_ip) or
                (confidence >= 0.4 and confidence < 0.85)
            )
        )

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

    # --- Phase 5: Verify top origin candidates ---
    verified_candidates = []
    for candidate in sorted(origin_only, key=lambda x: x["confidence"], reverse=True)[:5]:
        verification = _verify_origin_candidate(candidate["ip"], current_target)
        candidate["verified"] = verification["is_verified"]
        candidate["cert_match"] = verification["cert_match"]
        candidate["evidence"] = verification["evidence"]
        if verification["is_verified"]:
            candidate["confidence"] = round(min(candidate["confidence"] + 0.2, 1.0), 2)
        verified_candidates.append(candidate)

    # Update origin_only with verification results
    origin_only = verified_candidates + [c for c in origin_only if c["ip"] not in {v["ip"] for v in verified_candidates}]

    return {
        "domain": current_target,
        "cdn_detected": bool(cdn_providers),
        "cdn_providers": list(cdn_providers),
        "cdn_evidence": list(cdn_signals.values()) + ([f"header:{header_cdn}"] if header_cdn else []),
        "all_ips": all_flat_ips,
        "mx_ips": mx_ips,
        "spf_ips": spf_ips,
        "subdomain_ips": subdomain_ips,
        "origin_candidates": origin_only,
        "cdn_ips": cdn_only,
        "total_ips": len(all_flat_ips),
        "origin_count": len(origin_only),
        "cdn_count": len(cdn_only),
        "verified_count": sum(1 for c in origin_only if c.get("verified")),
        "recommendation": (
            f"Found {len(origin_only)} origin candidate(s) ({sum(1 for c in origin_only if c.get('verified'))} verified). "
            f"{len(cdn_only)} CDN edge IP(s). "
            f"Run network scan on origin IPs: {', '.join(c['ip'] for c in origin_only[:5])}"
            if origin_only else
            "No clear origin IPs found — try additional subdomain enumeration, "
            "historical DNS lookups, or CT log correlation"
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
