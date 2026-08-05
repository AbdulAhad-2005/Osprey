"""Canonical domain parsing for mcp-servers tools — Public Suffix List backed.

Single source of truth for registrable-domain (apex) extraction and validation.
Backed by the Public Suffix List via ``tldextract`` so every multi-part suffix
(``co.uk``, ``com.pk``, ``gov.in``, ``ac.nz`` … all ~9000 PSL entries) is handled
completely and stays current with the PSL — instead of a hand-maintained list
that silently omits most of the world's ccTLDs.

Refresh the suffix data by upgrading the ``tldextract`` package (its bundled PSL
snapshot), never by editing a list here. The extractor is pinned to the bundled
snapshot (``suffix_list_urls=()``) so it is deterministic and never touches the
network at runtime — important for scans that run air-gapped.
"""

from __future__ import annotations

import functools
import re
from urllib.parse import urlparse

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_ip(value: str) -> bool:
    return bool(_IPV4_RE.match(value)) or ":" in value


@functools.lru_cache(maxsize=1)
def _extractor():
    """Cached tldextract instance using the offline bundled PSL snapshot."""
    import tldextract  # provisioned in the Kali image (see kali-tools/Dockerfile)

    return tldextract.TLDExtract(suffix_list_urls=())


def normalize_host(raw: str) -> str:
    """Strip scheme, path, port, leading ``*.``/``www.`` → a bare lowercase host."""
    value = (raw or "").strip().lower().rstrip(".")
    if not value:
        return ""
    if "://" in value:
        value = urlparse(value).netloc or value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("?", 1)[0]
    if "@" in value:  # strip any userinfo
        value = value.rsplit("@", 1)[1]
    if value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            value = host
    if value.startswith("*."):
        value = value[2:]
    if value.startswith("www."):
        value = value[4:]
    return value


def registrable_apex(host: str) -> str:
    """Return the registrable (apex) domain via the Public Suffix List.

    ``a.b.example.co.uk`` -> ``example.co.uk``; ``foo.example.com`` ->
    ``example.com``. IPs and already-apex names are returned unchanged.
    """
    value = normalize_host(host)
    if not value or "." not in value or _is_ip(value):
        return value
    try:
        ext = _extractor()(value)
        if getattr(ext, "ipv4", "") or getattr(ext, "ipv6", ""):
            return value
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    # tldextract genuinely unavailable: honest last-two-labels — no fake PSL.
    labels = [lbl for lbl in value.split(".") if lbl]
    return ".".join(labels[-2:]) if len(labels) >= 2 else value


def is_registrable_domain(host: str) -> bool:
    """True if *host* is a registrable domain or a subdomain of one, per the PSL.

    Rejects bare TLDs, public suffixes with no registrable label, and non-domain
    strings (e.g. ``logo.png`` — ``png`` is not a public suffix).
    """
    value = normalize_host(host)
    if not value or "." not in value or _is_ip(value):
        return False
    try:
        ext = _extractor()(value)
        if getattr(ext, "ipv4", "") or getattr(ext, "ipv6", ""):
            return False
        return bool(ext.domain and ext.suffix)
    except Exception:
        pass
    labels = value.split(".")
    return len(labels) >= 2 and len(labels[-1]) >= 2


def is_same_apex(left: str, right: str) -> bool:
    """True when both hosts share the same registrable apex domain."""
    apex = registrable_apex(left)
    return bool(apex) and apex == registrable_apex(right)
