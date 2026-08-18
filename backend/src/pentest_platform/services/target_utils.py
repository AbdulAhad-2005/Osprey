"""Target normalization helpers — DNS resolution, IP detection, param extract."""

from __future__ import annotations

import functools as _functools
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout

# getaddrinfo has no per-call timeout; a hung resolver would pin a thread forever
# and freeze live-host expansion. Cap the wait and let the worker leak if DNS
# never returns — better than stalling the engine.
_RESOLVE_TIMEOUT_S = 5.0
_RESOLVE_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="dns4")


def _getaddrinfo(host: str, family: int, timeout: float):
    """socket.getaddrinfo with a hard wall-clock cap (returns [] on timeout)."""
    try:
        fut = _RESOLVE_POOL.submit(
            socket.getaddrinfo, host, None, family, socket.SOCK_STREAM,
        )
        return fut.result(timeout=timeout) or []
    except (OSError, FuturesTimeout):
        return []


_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# Tools whose CLI rejects hostnames or behaves better with a literal IPv4.
_IP_PREFERRED_TOOLS = frozenset({
    "nbtscan_netbios",
    "arp_scan_discovery",
})


def is_ipv4(value: str) -> bool:
    return bool(_IP_RE.match(value.strip()))


def resolve_ipv4(host: str, timeout: float = _RESOLVE_TIMEOUT_S) -> str | None:
    """Resolve a hostname to an IPv4 address. Returns None on failure or timeout."""
    host = host.strip()
    if not host or is_ipv4(host):
        return host if host else None
    results = _getaddrinfo(host, socket.AF_INET, timeout)
    return results[0][4][0] if results else None


def resolve_host_ip(host: str, timeout: float = _RESOLVE_TIMEOUT_S) -> str | None:
    """Resolve a hostname to any routable IP — IPv4 preferred, IPv6 fallback.

    Many CDN-fronted apexes (e.g. CloudFront) answer only with AAAA records;
    an IPv4-only lookup would wrongly classify them as dead. Returns None only
    when the name genuinely does not resolve (or DNS times out).
    """
    host = host.strip()
    if not host or is_ipv4(host):
        return host if host else None
    for family in (socket.AF_INET, socket.AF_INET6):
        results = _getaddrinfo(host, family, timeout)
        if results:
            return results[0][4][0]
    return None


def prefer_ip_for_tool(tool_name: str, target: str) -> tuple[str, str | None]:
    """Return (target_for_command, resolved_ip_or_none)."""
    if tool_name not in _IP_PREFERRED_TOOLS:
        return target, None
    if is_ipv4(target):
        return target, target
    ip = resolve_ipv4(target)
    if ip:
        return ip, ip
    return target, None


def extract_target(params: dict | None) -> str:
    """Pull target/url/domain/host/input_data/subdomains from tool params (priority order).

    ``input_data`` and ``subdomains`` are bulk-list params used by dnsx_resolve,
    httpx_probe, subdomain_takeover_check, etc. They must be recognised here so
    that seed injection does not silently overwrite a caller-provided host list
    with the engagement seed domain.
    """
    if not params:
        return ""
    for key in ("target", "url", "domain", "host", "input_data", "subdomains"):
        value = params.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def normalize_domain(raw: str) -> str:
    value = (raw or "").strip().lower().rstrip(".")
    if value.startswith("http://") or value.startswith("https://"):
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    if ":" in value and value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            value = host
    if value.startswith("*."):
        value = value[2:]
    return value


def looks_like_domain(value: str) -> bool:
    return bool(value and _DOMAIN_RE.match(value))


@_functools.lru_cache(maxsize=1)
def _tld_extractor():
    """Cached tldextract using the offline bundled PSL snapshot (no network)."""
    import tldextract

    return tldextract.TLDExtract(suffix_list_urls=())


def registrable_apex(raw: str) -> str:
    """Return the registrable (apex) domain from a FQDN, via the Public Suffix List.

    ``sub.scanme.nmap.org`` -> ``nmap.org``; ``a.b.example.co.uk`` ->
    ``example.co.uk``; ``foo.morth.gov.in`` -> ``morth.gov.in``. IPs pass through.

    Backed entirely by the PSL (``tldextract``) so every multi-part suffix is
    handled and stays current with the package, not a hand-maintained list.
    Refresh the data by upgrading ``tldextract``. (The mcp-servers runtime has
    an identical PSL helper in ``_core/domains.py``.)
    """
    value = normalize_domain(raw)
    if not value or is_ipv4(value) or ":" in value:
        return value
    try:
        ext = _tld_extractor()(value)
        if getattr(ext, "ipv4", "") or getattr(ext, "ipv6", ""):
            return value
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    # tldextract genuinely unavailable: honest last-two-labels — no fake PSL.
    labels = [lbl for lbl in value.split(".") if lbl]
    return ".".join(labels[-2:]) if len(labels) >= 2 else value


def normalize_ports_value(ports: str) -> str:
    """Strip a mistaken -p/--ports prefix from a ports parameter value.

    LLM often passes "-p22,80" or "-p 22,80" or "--ports 80,443" in the
    ports field itself; callers append their own -p flag downstream.
    """
    cleaned = (ports or "").strip()
    if not cleaned:
        return ""
    cleaned = re.sub(r"^--?p(?:orts?)?\s*", "", cleaned, flags=re.I).strip()
    if cleaned.startswith("-"):
        cleaned = cleaned.lstrip("-").strip()
    return cleaned
