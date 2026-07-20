"""CDN / origin probe — dig + curl signals (simplified, no hardcoded CDN IP tables).

Passive clues for whether a host sits behind a CDN and which IPs look like
mail/SPF/direct-subdomain candidates. Confidence is advisory — confirm before scan.
"""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "cdn_origin_probe"
CATEGORY = "recon"

CDN_CNAME_PATTERNS = {
    "cloudflare": [".cdn.cloudflare.net", ".cloudflare.net"],
    "akamai": [".akamaized.net", ".akamai.net", ".edgekey.net", ".edgesuite.net"],
    "fastly": [".fastly.net", ".fastlylb.net"],
    "cloudfront": [".cloudfront.net"],
    "azure_fd": [".azureedge.net", ".azurefd.net", ".trafficmanager.net"],
    "google_cloud": [".googleusercontent.com", ".ghs.google.com"],
}

CDN_HEADER_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status"],
    "akamai": ["x-akamai-transformed", "x-cache-key"],
    "fastly": ["x-fastly-request-id", "x-served-by"],
    "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "azure_fd": ["x-azure-ref"],
}


def build_command(**params: Any) -> str:
    domain = str(params.get("domain") or params.get("target") or "").strip()
    timeout = int(params.get("timeout") or 20)
    if not domain:
        raise ValueError("cdn_origin_probe requires domain or target")

    # Simple dig/curl script — flexible; agent can also invent platform_script variants.
    script = f"""
DOMAIN={shlex.quote(domain)}
TIMEOUT={timeout}
echo "=== DNS ==="
echo "CNAME: $(dig +short CNAME \"$DOMAIN\" 2>/dev/null)"
echo "A: $(dig +short A \"$DOMAIN\" 2>/dev/null)"
echo "AAAA: $(dig +short AAAA \"$DOMAIN\" 2>/dev/null)"
echo "NS: $(dig +short NS \"$DOMAIN\" 2>/dev/null)"
echo "MX: $(dig +short MX \"$DOMAIN\" 2>/dev/null)"
echo "=== MX_IPS ==="
for mx in $(dig +short MX \"$DOMAIN\" 2>/dev/null | awk '{{print $NF}}' | tr -d '.'); do
  [ -z \"$mx\" ] && continue
  echo \"MX_IP: $mx -> $(dig +short A \"$mx\" 2>/dev/null | head -1)\"
done
echo "=== SPF ==="
dig +short TXT \"$DOMAIN\" 2>/dev/null | grep -i spf || true
echo "=== SUBS ==="
for sub in mail smtp pop imap webmail ftp vpn gateway direct origin owa autodiscover; do
  ip=$(dig +short A \"$sub.$DOMAIN\" 2>/dev/null | head -1)
  [ -n \"$ip\" ] && echo \"SUBDOMAIN_IP: $sub.$DOMAIN -> $ip\"
done
echo "=== HEADERS ==="
curl -sI --max-time \"$TIMEOUT\" \"https://$DOMAIN\" 2>/dev/null | head -25 || true
curl -sI --max-time \"$TIMEOUT\" \"http://$DOMAIN\" 2>/dev/null | head -15 || true
""".strip()
    return f"bash -c {shlex.quote(script)}"


def parse(result: ToolResult) -> dict[str, Any]:
    stdout = result.raw_stdout or ""
    cdn_provider = None
    current_ips: list[str] = []
    mx_ips: list[str] = []
    subdomain_ips: dict[str, str] = {}
    spf_ips: list[str] = []
    evidence: list[str] = []
    section = ""

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("=== "):
            section = line.strip("= ").lower()
            continue
        if section.startswith("dns"):
            if line.startswith("CNAME:"):
                cname = line.split(":", 1)[1].strip().lower()
                for provider, patterns in CDN_CNAME_PATTERNS.items():
                    if any(p in cname for p in patterns):
                        cdn_provider = provider
                        evidence.append(f"CNAME->{provider}: {cname}")
            elif line.startswith("A:"):
                current_ips.extend(line.split(":", 1)[1].split())
            elif line.startswith("AAAA:"):
                current_ips.extend(line.split(":", 1)[1].split())
        elif section.startswith("mx"):
            if "->" in line:
                ip = line.split("->", 1)[1].strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    mx_ips.append(ip)
                    evidence.append(line)
        elif section.startswith("spf"):
            spf_ips.extend(re.findall(r"ip4:(\d{1,3}(?:\.\d{1,3}){3})", line))
        elif section.startswith("sub"):
            if "->" in line:
                left, ip = [x.strip() for x in line.split("->", 1)]
                host = left.split(":", 1)[-1].strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    subdomain_ips[host] = ip
                    evidence.append(line)
        elif section.startswith("header"):
            for provider, sigs in CDN_HEADER_SIGNATURES.items():
                if any(s in line.lower() for s in sigs):
                    cdn_provider = cdn_provider or provider
                    evidence.append(f"header:{provider}: {line[:120]}")

    candidates = []
    for ip in sorted(set(mx_ips + spf_ips + list(subdomain_ips.values()))):
        signals = []
        score = 0.0
        if ip in mx_ips:
            signals.append("mx")
            score += 0.4
        if ip in spf_ips:
            signals.append("spf")
            score += 0.3
        if ip in subdomain_ips.values():
            signals.append("direct_subdomain")
            score += 0.3
        if ip not in current_ips:
            signals.append("not_edge_a_record")
            score += 0.15
        candidates.append(
            {"ip": ip, "confidence": round(min(score, 1.0), 2), "signals": signals}
        )
    candidates.sort(key=lambda x: -x["confidence"])

    return {
        "cdn_provider": cdn_provider,
        "edge_ips": list(dict.fromkeys(current_ips)),
        "origin_candidates": candidates,
        "evidence": evidence[:40],
        "count": len(candidates),
        "note": (
            "Advisory only — confirm origin before port-scanning. "
            "Prefer scanning candidates, not CDN edge IPs."
        ),
    }


def run(
    domain: str = "",
    target: str = "",
    timeout: int = 20,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 120,
) -> dict[str, Any]:
    params = {
        "domain": domain or target,
        "timeout": timeout,
        "additional_args": additional_args,
    }
    return run_tool(
        TOOL_NAME,
        build_command(**params),
        params=params,
        timeout=exec_timeout,
        use_cache=use_cache,
        use_recovery=use_recovery,
        parse_fn=parse,
    )
