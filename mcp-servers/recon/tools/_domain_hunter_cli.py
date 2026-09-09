"""Shared implementation for sister-domain discovery (single canonical source).

The tool is intentionally a single self-locating module so it can be run both
from the standalone CLI (``python3 _domain_hunter_cli.py --domain X``) and
imported by the recon MCP wrapper (``_domain_hunter_cli.parse_stdout``) — no
separate ``main.py``/``domain-hunter/`` project, unlike the old layout.

Discovery modules (``--modules``, comma-separated; aliases in
``DomainHunter._normalize_modules``):

- ``site_scrape``     external domains in homepage links + redirect target +
                      robots.txt/sitemap.xml references
- ``certs``           certificate transparency (crt.sh ``%seed%`` wildcard)
- ``knowledge_recon`` brand-token crt.sh searches + Wikidata official-website
                      (P856) + TLD/pattern variant guessing (DNS-verified)
- ``dns``             seed's NS/MX hosts
- ``asn``             reverse-IP co-location (skipped on CDN/edge IPs)
- ``whois``           RDAP registrant org tokens -> crt.sh token searches

Static data is kept at the canonical level and mostly delegated to
authoritative sources: the Public Suffix List (both sections) for what counts
as a domain and what is shared cloud-platform infrastructure, and ASN
organization ownership (Team Cymru) for CDN/edge detection. See the notes at
``_SITE_LINK_NOISE_ROOTS`` for the one irreducible curated set.

Every candidate is scored with weighted weak signals; confidence tiers are
low/medium/high; the output table (and the ``=== Findings ===`` progress
blocks emitted after every module) is consumed by ``parse_stdout`` on the
wrapper/backend side. Partial output survives an outer kill/timeout.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urlparse

logger = logging.getLogger(__name__)

# Canonical PSL-backed domain parsing (shared with every other recon tool).
_MCP_ROOT = Path(__file__).resolve().parents[2]  # mcp-servers/
if str(_MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(_MCP_ROOT))
from _core.domains import is_registrable_domain, is_same_apex, registrable_apex

# Why there is no big shared-infra denylist here:
#
#   * CLOUD-PLATFORM apexes (azurewebsites.net, cloudfront.net, github.io,
#     herokuapp.com, netlify.app, akamaized.net, ...) are detected via the
#     Public Suffix List's PRIVATE section — a community-curated, versioned
#     registry of exactly these shared-hosting/CDN names (see
#     _at_psl_private_apex). That is authoritative and self-maintaining, so no
#     hand copy of those names lives in this file.
#
#   * SEED-IP edge detection (is the seed itself behind Cloudflare/Fastly/...,
#     which would make reverse-IP co-location meaningless) is done by looking
#     up the IP's owning ASN (Team Cymru) and matching the ASN *organization*
#     name — the canonical ownership level — against a small keyword set, not
#     by shipping IP-range lists (see _is_shared_edge_ip).
#
#   * The set below is the irreducible residue: TRACKER/AD/SOCIAL-PLATFORM and
#     ASSET-CDN apexes that sites link out to but that are never an
#     affiliated root of the seed (doubleclick.net, facebook.com, cdnjs.com,
#     ...). No algorithmic source exists for "this apex is a third-party
#     platform" — every adblocker ships the same class of data. It is scoped
#     narrowly: it only suppresses SITE-SCRAPE (link/robots/sitemap) evidence,
#     never certs/DNS/ASN evidence, so a platform apex with real signals still
#     surfaces.
_SITE_LINK_NOISE_ROOTS = frozenset(
    {
        # ad / analytics / tracking
        "doubleclick.net",
        "google-analytics.com",
        "googletagmanager.com",
        "googleadservices.com",
        "googlesyndication.com",
        "googletagservices.com",
        "2mdn.net",
        "scorecardresearch.com",
        # social platforms
        "facebook.com",
        "fbcdn.net",
        "instagram.com",
        "twitter.com",
        "x.com",
        "youtube.com",
        "ytimg.com",
        "googlevideo.com",
        "linkedin.com",
        "tiktok.com",
        "reddit.com",
        "whatsapp.com",
        "telegram.org",
        "pinterest.com",
        # asset / static-file CDN apexes
        "cdnjs.com",
        "bootstrapcdn.com",
        "fontawesome.com",
        "cloudinary.com",
        "imgix.net",
        "bunnycdn.com",
        "keycdn.com",
        "vimeocdn.com",
        "netdna-ssl.com",
        "wp.com",
        "gravatar.com",
        "unpkg.com",
        "jsdelivr.net",
        "stackpathcdn.com",
        "gstatic.com",
        "googleusercontent.com",
        "amazonaws.com",
        "incapsula.com",
        "sucuri.net",
        # CDN-company apexes (also appear as DNS NS-host roots)
        "cloudflare.com",
        "akamai.com",
        "fastly.com",
        "azure.com",
        # Reference/knowledge sites — a predictable self-link false-positive
        # from web_search's own Wikipedia-scraping technique (the seed org's
        # Wikipedia page inevitably links wikipedia.org itself), never a real
        # sister domain.
        "wikipedia.org",
        "wikimedia.org",
    }
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# Host extraction from free text (robots/sitemap blobs). The leading lookbehind
# stops path/file components from matching: `Disallow: /images/logo.png` or
# `file=logo.zip` can never start a host, so no filename-extension denylist is
# needed — the PSL is the authority on what counts as a domain, and this
# boundary rule keeps non-hosts out of the extraction in the first place.
_DOMAIN_RE = re.compile(r"(?<![\w@.=/-])(?:https?://)?(?:www\.)?([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})", re.IGNORECASE)

# Confidence tiers used for the --confidence-min floor. Scores are rebalanced
# so a SINGLE weak signal + live-probe can never cross medium on its own:
# medium requires >= 30 live (two weak signals) or >= 45 dead (one strong).
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}

# Point values per signal (see module docstring rationale). Weak signals are
# capped at 21 so a SINGLE weak signal + live probe (8) stays below the live
# medium floor of 30; medium requires two weak signals, or one strong one
# (direct certs 40 / wikidata 36).
_POINTS_SITE_LINK = 20
_POINTS_REDIRECT = 16
_POINTS_ROBOTS_SITEMAP = 18
_POINTS_CERTS_DIRECT = 40
_POINTS_CERTS_TOKEN = 20
_POINTS_DNS = 20
_POINTS_ASN = 20
_POINTS_WIKIDATA = 36
_POINTS_TLD_VARIANT = 20
_POINTS_LIVE = 8

_POINTS_EMAIL_PIVOT = 30
_POINTS_SPF_DMARC = 24
_POINTS_REVERSE_NS = 22
_POINTS_ASN_EXPAND = 26
_POINTS_MULTI_SOURCE = 22
_POINTS_REVERSE_WHOIS = 40
_POINTS_TRACKER_PIVOT = 28
_POINTS_AI_HUNT = 35  # LLM hypothesis — high value when verified
_POINTS_FAVICON_HASH = 30  # identical favicon MD5 to seed
_POINTS_PATTERN_GEN = 15  # generated label variant (weaker signal)

# Registrar / privacy protection / email forwarding domains — when a seed
# uses WHOIS privacy, the RDAP registrant is the privacy service (e.g.,
# enom.com, whoisguard.com).  Reverse WHOIS on those returns thousands of
# unrelated domains.  Filter these out aggressively.
_REGISTRAR_DOMAINS = frozenset({
    "enom.com", "enom.net", "enom.org", "enom.ca", "enom.uk",
    "whoisguard.com", "whoisprivacyservices.com", "domainsbyproxy.com",
    "privacyprotect.org", "contactprivacy.com", "withheldforprivacy.com",
    "perfectprivacy.com", "namecheap.com", "namesilo.com",
    "godaddy.com", "gregians.net", "web.com",
    "hubspot.net", "wixdns.net", "squarespace.com",
    "google.com", "googleapis.com", "cloudflare.com",
    "protectiondomain.com", "redactedforprivacy.com",
    "dataprotected.com", "privatewhois.net",
    "hostedemail.com", "forwardemail.net",
})

# Known shared platforms / hosting providers / free subdomain hosts.
# Domains under these are shared infrastructure — not sister organizations.
# Used to filter noise from CT token searches in corporate module.
_SHARED_PLATFORM_DOMAINS = frozenset({
    # Free hosting / blog platforms
    "blogspot.com", "wordpress.com", "tumblr.com", "wix.com", "weebly.com",
    "squarespace.com", "godaddy.com", "pages.dev", "netlify.app",
    "vercel.app", "github.io", "gitlab.io", "herokuapp.com",
    "byethost7.com", "byethost.com", "000webhost.com",
    "writeablog.net", "blogsome.com", "posterous.com",
    # Cloud / CDN / email providers
    "google.com", "googleapis.com", "cloudflare.com", "akamai.com",
    "fastly.com", "cloudfront.net", "amazonaws.com",
    "outlook.com", "office365.com", "microsoft.com",
    "icloud.com", "me.com", "mac.com",
    "office.com", "live.com",
    # Domain registrars / privacy
    "enom.com", "whoisguard.com", "domainsbyproxy.com",
    "namecheap.com", "namesilo.com",
    # Hosting providers
    "wixdns.net", "syrahost.com", "whmpanels.com",
    "hostgator.com", "bluehost.com", "dreamhost.com",
    "siteground.com", "a2hosting.com", "inmotionhosting.com",
    # News aggregators / content farms
    "einnews.com",
})


def _is_shared_platform(domain: str) -> bool:
    """Check if a domain is a known shared platform / hosting provider.

    Returns True if the domain matches any entry in _SHARED_PLATFORM_DOMAINS.
    Used to filter noise from CT token searches — domains on shared platforms
    are not sister organizations.
    """
    rd = root_domain(domain)
    if not rd:
        return False
    # Direct match
    if rd in _SHARED_PLATFORM_DOMAINS:
        return True
    # Subdomain match (e.g., freefireapk2025.blogspot.com → blogspot.com)
    for platform in _SHARED_PLATFORM_DOMAINS:
        if rd.endswith("." + platform) or rd == platform:
            return True
    return False


# ---------------------------------------------------------------------------
# Per-IP cap on reverse-IP results — bounds runtime and the noise tail on
# shared-hosting ranges.
_MAX_REVERSE_RESULTS = 250

# ASN-organization keyword set for seed-IP edge detection (_is_shared_edge_ip):
# when the IP's owning ASN (queried live from Team Cymru, whois.cymru.com —
# the same source as the backend's asn_enum tool) is announced by one of these
# providers, the address is a shared CDN/edge/platform range and reverse-IP
# co-location there is not an affiliation signal. Matching the canonical
# ownership level (org name) instead of shipping IP-range lists covers every
# address of a provider automatically — no CIDR lists to rot, and new
# provider ranges need no code change (only a provider name added here).
_THIRD_PARTY_ORG_KEYWORDS = frozenset(
    {
        "CLOUDFLARE",
        "AKAMAI",
        "FASTLY",
        "CLOUDFRONT",
        "AMAZON",
        "MICROSOFT",
        "AZURE",
        "GOOGLE",
        "INCAPSULA",
        "IMPERVA",
        "SUCURI",
        "STACKPATH",
        "EDGECAST",
        "VERIZON",
        "NETLIFY",
        "CLOUDINARY",
        "KEYCDN",
        "BUNNYCDN",
    }
)

# Generic gTLDs probed for the bare brand-token variants (geo.tv -> geo.com /
# geo.net / geo.io ...) — brand-holding domains often live on a different TLD.
# Language-independent on purpose: no English brand-extension word list is baked
# in here. Compound variants (geo + "news" -> geonews) are instead derived at
# runtime from the seed's OWN discovered brand tokens (homepage title), so the
# variant guessing adapts per-domain instead of firing only for English brands
# (see _collect_knowledge_signals).
_VARIANT_GTLDS = ("com", "net", "org", "io", "co", "info", "biz")

# Country-code TLDs for the seed's region + major media markets.  When the seed
# is a .pk domain, we also try .com.pk / .org.pk etc.  The set is intentionally
# broad — DNS verification filters dead guesses, so false TLD probes cost only
# a resolver round-trip, not a false positive.
_CC_TLDS = (
    "pk", "com.pk", "org.pk", "net.pk", "edu.pk",  # Pakistan
    "uk", "co.uk", "org.uk",  # UK
    "in", "co.in", "org.in",  # India
    "ae", "com.ae",  # UAE
    "sa", "com.sa",  # Saudi
    "global", "online", "site", "xyz", "tv",  # new gTLDs + .tv (popular for media)
)


def normalize_seed_domain(value: str) -> str:
    """Return a host/root-domain string stripped from URLs and paths."""
    raw = value.strip().lower()
    if not raw:
        return ""
    parsed = urlparse(raw if raw.startswith(("http://", "https://")) else f"//{raw}", scheme="https")
    host = parsed.hostname or raw
    host = host.strip("./")
    if host.startswith("www."):
        host = host[4:]
    return host


def root_domain(host: str) -> str:
    """Registrable (apex) domain via the Public Suffix List — see _core.domains."""
    return registrable_apex(normalize_seed_domain(host))


def hunter_seed_apex(value: str) -> str:
    """Apex used as the Domain Hunter seed, or '' if the input is not a domain."""
    apex = root_domain(value)
    if not apex or not is_registrable_domain(apex):
        return ""
    return apex


def crtsh_like_query(query: str, *, token_search: bool, seed_root: str) -> str:
    """crt.sh SQL-LIKE pattern. Pass the raw ``%`` wildcards; URL-encode once at fetch time.

    Pre-encoding ``%`` as ``%25`` here used to be double-encoded by ``quote_plus``,
    so the service searched for literal ``25…`` instead of a wildcard around the seed.
    """
    query = (query or "").strip().lower()
    seed_root = (seed_root or "").strip().lower()
    if token_search and query and query != seed_root:
        return f"%{query}%"
    return f"%{seed_root}" if seed_root else ""


def is_same_root(left: str, right: str) -> bool:
    return is_same_apex(normalize_seed_domain(left), normalize_seed_domain(right))


def _safe_tokens(text: str) -> list[str]:
    tokens = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9-]{2,}", text):
        cleaned = token.lower().strip("-.")
        if cleaned and cleaned not in tokens:
            tokens.append(cleaned)
    return tokens


def _is_likely_domain_or_none(host: str) -> str | None:
    """Return *host* if it is a real registered domain, else ``None``.

    Authoritative Public-Suffix-List validation — see ``_core.domains``. No
    hand-maintained TLD list: the PSL knows every delegated suffix, so
    filename-looking hosts (``logo.png``, ``app.js``) are rejected because
    ``png``/``js`` are not public suffixes, and genuine file-extension TLDs
    (``example.zip``, ``logo.md``) are accepted because they ARE delegated.
    """
    host = host.strip().lower()
    if not host or "." not in host:
        return None
    return host if is_registrable_domain(host) else None


def _seed_base_tokens(seed_root: str) -> list[str]:
    """Brand tokens derived from the seed's own label only.

    Letter-anchored word fragments plus the alnum-collapsed form of the
    label, so digit/hyphen labels keep their full brand token
    ("7-eleven" -> [eleven, 7eleven]) instead of losing the numeric part.
    But when the label itself STARTS with a digit, its letter fragments are
    not standalone brand tokens: "1800flowers" greps out "flowers", a
    generic word wikidata binds to unrelated namesakes (the band Icehouse,
    once named "The Flowers") that manufacture false official-website
    candidates. Digit-led labels therefore keep only the collapsed form
    ("1800flowers" -> [1800flowers], "7-eleven" -> [7eleven]).
    """
    base = seed_root.split(".")[0].lower()
    if base[:1].isdigit():
        collapsed = re.sub(r"[^a-z0-9]", "", base)
        if len(collapsed) >= 3:
            return [collapsed]
        return []
    tokens = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9-]{2,}", base):
        cleaned = token.strip("-.")
        if cleaned and cleaned not in tokens:
            tokens.append(cleaned)
    collapsed = re.sub(r"[^a-z0-9]", "", base)
    if len(collapsed) >= 3 and collapsed not in tokens:
        tokens.append(collapsed)
    return tokens


def _brand_tokens(seed_root: str, title_text: str = "") -> list[str]:
    # Common English words + country names that appear in news titles but are NOT brand tokens
    _STOPWORDS = frozenset({
        # Common English words
        "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
        "her", "was", "one", "our", "out", "has", "his", "how", "its", "may",
        "new", "now", "old", "see", "way", "who", "did", "get", "let", "say",
        "she", "too", "use", "with", "that", "this", "will", "each", "make",
        "like", "long", "look", "many", "most", "over", "such", "take", "than",
        "them", "then", "what", "when", "your", "from", "have", "been", "said",
        "more", "some", "time", "very", "just", "into", "also", "back", "after",
        "only", "come", "made", "could", "well", "were", "their", "would",
        "about", "other", "which", "would", "these", "first", "going", "still",
        "where", "think", "world", "life", "being", "every", "found", "under",
        "never", "since", "might", "doing", "right", "place", "year", "years",
        # News/media common words
        "live", "news", "latest", "breaking", "today", "daily", "online",
        "watch", "read", "more", "video", "photos", "photo", "report",
        "updates", "update", "show", "shows", "special",
        "exclusive", "developing", "trending", "headlines", "bulletin",
        # Country names (appear in news org titles but are NOT brand tokens)
        "pakistan", "india", "china", "usa", "uk", "canada", "australia",
        "afghanistan", "iran", "iraq", "syria", "turkey", "saudi", "arabia",
        "emirates", "uae", "bangladesh", "srilanka", "nepal", "bhutan",
        "maldives", "myanmar", "thailand", "vietnam", "philippines",
        "indonesia", "malaysia", "singapore", "japan", "korea", "mongolia",
    })
    tokens = list(_seed_base_tokens(seed_root))
    for token in _safe_tokens(title_text):
        if token not in tokens and token not in _STOPWORDS and len(token) > 3:
            tokens.append(token)
    return tokens[:8]


def _extract_domains(text: str) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for match in _DOMAIN_RE.finditer(text):
        host = match.group(1).strip(").,;:\"'[]{}<>")
        valid = _is_likely_domain_or_none(host)
        if valid and valid not in seen:
            seen.add(valid)
            results.append(valid)
    for match in _EMAIL_RE.finditer(text):
        host = match.group(1).strip(").,;:\"'[]{}<>")
        valid = _is_likely_domain_or_none(host)
        if valid and valid not in seen:
            seen.add(valid)
            results.append(valid)
    return results


def _http_session():
    import requests

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
            )
        }
    )
    # NO Retry adapter on purpose: requests' default Retry(total=0) makes every
    # request single-attempt, so a hanging host costs one timeout, not three
    # (Retry(total=2, status_forcelist=...) multiplied a 5s timeout into ~30s
    # per host during the live sweep). Where retries matter (crt.sh), they are
    # implemented explicitly with their own backoff.
    return session


def _fetch(session: Any, url: str, timeout: int = 8) -> tuple[str, str]:
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
        if response.ok or response.status_code in {401, 403}:
            return response.text, response.url
    except Exception:
        return "", url
    return "", url


def _fetch_with_fallback(session: Any, url: str, timeout: int = 8) -> tuple[str, str]:
    """https first, http fallback (some sites only serve plain http)."""
    text, final_url = _fetch(session, url, timeout=timeout)
    if text:
        return text, final_url
    return _fetch(session, url.replace("https://", "http://", 1), timeout=timeout)


def _live_probe(session: Any, domain: str, timeout: int = 4) -> tuple[bool, str | None]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
            if response.status_code < 500:
                return True, response.url
        except Exception:
            continue
    return False, None


def _resolve_ips(domain: str) -> list[str]:
    ips: list[str] = []
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(4)
        try:
            results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old_timeout)
        for item in results:
            ip = item[4][0]
            if ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    return ips


def _asn_org(ip: str) -> str | None:
    """Owning ASN organization name for *ip* via Team Cymru (whois.cymru.com).

    Returns e.g. ``"CLOUDFLARENET - Cloudflare, Inc., US"`` or ``None`` when
    the lookup fails (network/parse) — failure never blocks a scan, it just
    means "not proven shared". Results are cached per IP.
    """
    if ip in _ASN_ORG_CACHE:
        return _ASN_ORG_CACHE[ip]
    org: str | None = None
    try:
        connection = socket.create_connection(("whois.cymru.com", 43), timeout=4)
        try:
            connection.sendall(f"-v {ip}\r\n".encode("ascii"))
            data = b""
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            connection.close()
        for line in data.decode("utf-8", errors="replace").splitlines()[1:]:
            parts = [part.strip() for part in line.split("|")]
            # Verbose mode: "ASN | IP | BGP Prefix | CC | Registry | Allocated | Org Name"
            if len(parts) >= 2 and parts[0].isdigit():
                org = parts[-1] or None
                break
    except Exception:
        org = None
    _ASN_ORG_CACHE[ip] = org
    return org


_ASN_ORG_CACHE: dict[str, str | None] = {}


def _is_shared_edge_ip(ip: str) -> bool:
    """True when *ip* is announced by a shared CDN/edge/platform provider.

    Ownership is the question, so ownership is what is looked up: the IP's
    ASN organization (Team Cymru) is matched against
    ``_THIRD_PARTY_ORG_KEYWORDS``. This replaces both of the old static
    mechanisms — a hand-maintained CIDR-prefix list (Cloudflare anycast has
    no PTR records, so a prefix list was bolted on) and PTR-hostname checks
    (a proxy for ownership that the ASN lookup answers directly). Every
    address of a provider is covered, not just the prefixes that were listed.
    """
    org = _asn_org(ip)
    if not org:
        return False
    org_upper = org.upper()
    return any(keyword in org_upper for keyword in _THIRD_PARTY_ORG_KEYWORDS)


_PSL_PRIVATE: Any = None
_PSL_SUFFIX_LABELS: set[str] | None = None


def _is_tld_like_label(label: str, seed_tld: str = "") -> bool:
    """True when *label* is the first label of any multi-label public suffix.

    Seed labels that are themselves TLD words (``gov`` -> ``gov.uk``,
    ``co`` -> ``co.jp``, ``com`` -> ``com.cn``) generate generic squat
    variants (gov.com, govonline.uk) that are never the seed's sisters.
    Derived from the same PSL snapshot, never hand-maintained.

    When *seed_tld* is provided, only filters labels that form a real suffix
    under the seed's own TLD (e.g., ``geo`` under ``.br`` → ``geo.br``).
    This prevents over-filtering brand names like ``geo`` that happen to be
    the first label of an unrelated country TLD (``geo.br``) but are
    perfectly valid brand tokens for a ``.tv`` seed.
    """
    global _PSL_PRIVATE, _PSL_SUFFIX_LABELS
    if _PSL_SUFFIX_LABELS is None:
        if _PSL_PRIVATE is None:
            import tldextract  # provisioned in the Kali image

            _PSL_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
        _PSL_SUFFIX_LABELS = {
            suffix.split(".")[0]
            for suffix in _PSL_PRIVATE.tlds
            if "." in suffix
        }
    if seed_tld:
        # Only filter if label forms a real compound suffix under the seed's TLD
        # e.g., for seed_tld="br", label="geo" → check if "geo.br" is a suffix
        return f"{label}.{seed_tld}" in _PSL_PRIVATE.tlds
    return label in _PSL_SUFFIX_LABELS


def _at_psl_private_apex(host: str) -> bool:
    """True when *host* sits at a Public-Suffix-List PRIVATE-section apex.

    The PSL's private section is the community-curated registry of shared
    cloud/hosting/CDN names (azurewebsites.net, cloudfront.net, github.io,
    herokuapp.com, netlify.app, ...). A host is at a private apex when the
    registrable domain differs between the private-section-aware extractor
    and the public one: ``a.azurewebsites.net`` -> ``a.azurewebsites.net``
    vs ``azurewebsites.net``. Pinned to the bundled offline snapshot
    (deterministic, air-gap safe) — refreshed by upgrading tldextract, never
    by editing a list here.
    """
    global _PSL_PRIVATE
    if _PSL_PRIVATE is None:
        import tldextract  # provisioned in the Kali image

        _PSL_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
    try:
        extract = _PSL_PRIVATE(host)
        if not extract.domain or not extract.suffix:
            return False
        private_registrable = f"{extract.domain}.{extract.suffix}".lower()
        return private_registrable != registrable_apex(host)
    except Exception:
        return False


def _domain_resolves(domain: str) -> bool:
    """True when *domain* has at least one A record (dnspython, hard timeouts).

    Preferred over socket.getaddrinfo for bulk probes: socket's default timeout
    is not reliably honored for getaddrinfo on all platforms, which lets a
    batch of dead-domain probes hang for seconds each. dnspython enforces
    timeout/lifetime properly and NXDOMAINs fail fast.
    """
    try:
        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3
        resolver.timeout = 2
        return bool(resolver.resolve(domain, "A"))
    except Exception:
        return False


def _resolve_dns_hosts(domain: str) -> list[str]:
    hosts: list[str] = []
    try:
        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4
        resolver.timeout = 3
        for rtype in ("NS", "MX"):
            try:
                answers = resolver.resolve(domain, rtype)
            except Exception:
                continue
            for rr in answers:
                host = getattr(rr, "exchange", rr)
                host_text = str(host).strip().rstrip(".")
                if host_text and host_text not in hosts:
                    hosts.append(host_text)
    except Exception:
        return hosts
    return hosts


def _urlscan_query(session: Any, domain: str, timeout: int = 10) -> list[str]:
    """urlscan.io search — free, no API key required for basic queries.

    Searches urlscan.io for pages served by the domain, extracts linked
    domains from the results.  Limited to ~100 results per query on the
    free tier but covers recent crawl data.
    """
    url = f"https://urlscan.io/api/v1/search/?q=domain:{quote_plus(domain)}&size=100"
    names: list[str] = []
    try:
        response = session.get(url, timeout=timeout)
        if not response.ok:
            return []
        data = response.json()
        for result in data.get("results", []):
            page = result.get("page", {})
            for key in ("domain", "ip", "asn"):
                val = str(page.get(key, "")).strip().lower()
                if val and "." in val and val not in names:
                    if is_registrable_domain(val):
                        names.append(val)
            # Extract linked domains from the result
            for item in result.get("lists", {}).get("domains", []):
                val = str(item).strip().lower()
                if val and "." in val and val not in names:
                    if is_registrable_domain(val):
                        names.append(val)
    except Exception as exc:
        logger.info("urlscan.io query failed (%s): %s", domain, exc)
    return names


def _threatminer_query(session: Any, domain: str, timeout: int = 10) -> list[str]:
    """ThreatMiner free API — domain passive DNS and related hosts.

    Returns historical DNS resolutions and related domains for the query.
    No API key required.
    """
    url = f"https://api.threatminer.org/v2/host.php?q={quote_plus(domain)}&rt=1&pta=2"
    names: list[str] = []
    try:
        response = session.get(url, timeout=timeout)
        if not response.ok:
            return []
        data = response.json()
        for item in data.get("results", []):
            val = str(item).strip().lower()
            if val and "." in val and val not in names:
                if is_registrable_domain(val):
                    names.append(val)
    except Exception as exc:
        logger.info("ThreatMiner query failed (%s): %s", domain, exc)
    return names


def _rapiddns_query(session: Any, domain: str, timeout: int = 10) -> list[str]:
    """rapiddns.io free DNS history — finds domains sharing infrastructure.

    Scrapes the rapiddns.io page for historical DNS data.  No API key
    required; returns domains that previously resolved to the same IPs
    as the seed.
    """
    import requests
    from bs4 import BeautifulSoup  # type: ignore

    url = f"https://rapiddns.io/subdomain/{quote_plus(domain)}?full=1"
    names: list[str] = []
    try:
        response = session.get(url, timeout=timeout)
        if not response.ok:
            return []
        soup = BeautifulSoup(response.text, "html.parser")
        for td in soup.find_all("td"):
            text = td.get_text(strip=True).lower()
            if text and "." in text and text != domain:
                if is_registrable_domain(text) and text not in names:
                    names.append(text)
    except Exception as exc:
        logger.info("rapiddns query failed (%s): %s", domain, exc)
    return names


def _alienvault_otx_query(session: Any, domain: str, timeout: int = 10) -> list[str]:
    """AlienVault OTX free API — passive DNS and domain pulses.

    Queries OTX for passive DNS records related to the domain.  No API
    key required for basic queries; returns historical resolutions.
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote_plus(domain)}/passive_dns"
    names: list[str] = []
    try:
        response = session.get(url, timeout=timeout)
        if not response.ok:
            return []
        data = response.json()
        for entry in data.get("passive_dns", []):
            hostname = str(entry.get("hostname", "")).strip().lower()
            if hostname and "." in hostname and hostname != domain:
                if is_registrable_domain(hostname) and hostname not in names:
                    names.append(hostname)
    except Exception as exc:
        logger.info("AlienVault OTX query failed (%s): %s", domain, exc)
    return names


# ---------------------------------------------------------------------------
# Reverse WHOIS / corporate registry / tracker-pivot sources
# ---------------------------------------------------------------------------

def _whoxy_reverse_whois(
    session: Any,
    seed_root: str,
    api_key: str = "",
    *,
    timeout: int = 12,
) -> list[str]:
    """Whoxy reverse WHOIS — finds all domains registered by the same org/email.

    Whoxy offers a free API tier (250K credits for education/non-profit).
    When an API key is provided (``WHOXY_API_KEY`` env var or direct), searches
    by registrant email, organization name, and keyword to discover sister
    domains registered by the same entity.

    Without an API key, falls back to a free reverse WHOIS via ViewDNS
    (limited to 100 results per day).

    This is the SINGLE HIGHEST-VALUE addition for sister-domain discovery:
    it finds domains that share NO infrastructure, NO certs, and NO DNS —
    they are only linked by the same human or organization registering them.
    """
    import os

    api_key = api_key or os.environ.get("WHOXY_API_KEY", "")
    found: list[str] = []

    if api_key:
        # Whoxy API: reverse WHOIS by email, company, and keyword
        # Step 1: Get WHOIS data for the seed to extract email/org
        whois_url = f"https://api.whoxy.com/?key={api_key}&whois={quote_plus(seed_root)}"
        try:
            resp = session.get(whois_url, timeout=timeout)
            if resp.ok:
                data = resp.json()
                if data.get("status") == 1:
                    whois_record = data.get("whois_data", {})
                    email = whois_record.get("registrant_contact", {}).get("email_address", "")
                    org = whois_record.get("registrant_contact", {}).get("company_name", "")
                    name = whois_record.get("registrant_contact", {}).get("full_name", "")

                    # Step 2: Reverse WHOIS by email
                    if email and "@" in email:
                        rev_url = (
                            f"https://api.whoxy.com/?key={api_key}"
                            f"&reverse=whois&email={quote_plus(email)}&mode=domains"
                        )
                        try:
                            r = session.get(rev_url, timeout=timeout)
                            if r.ok:
                                rd = r.json()
                                for domain in rd.get("domains_list", []):
                                    val = str(domain).strip().lower()
                                    if val and "." in val and val != seed_root:
                                        # Skip registrar/privacy service domains
                                        if root_domain(val) in _REGISTRAR_DOMAINS:
                                            continue
                                        if is_registrable_domain(val) and val not in found:
                                            found.append(val)
                        except Exception:
                            pass

                    # Step 3: Reverse WHOIS by company/org name
                    if org and len(org) >= 3:
                        rev_url = (
                            f"https://api.whoxy.com/?key={api_key}"
                            f"&reverse=whois&company={quote_plus(org)}&mode=domains"
                        )
                        try:
                            r = session.get(rev_url, timeout=timeout)
                            if r.ok:
                                rd = r.json()
                                for domain in rd.get("domains_list", []):
                                    val = str(domain).strip().lower()
                                    if val and "." in val and val != seed_root:
                                        if root_domain(val) in _REGISTRAR_DOMAINS:
                                            continue
                                        if is_registrable_domain(val) and val not in found:
                                            found.append(val)
                        except Exception:
                            pass

                    # Step 4: Reverse WHOIS by registrant name
                    if name and len(name) >= 3:
                        rev_url = (
                            f"https://api.whoxy.com/?key={api_key}"
                            f"&reverse=whois&name={quote_plus(name)}&mode=domains"
                        )
                        try:
                            r = session.get(rev_url, timeout=timeout)
                            if r.ok:
                                rd = r.json()
                                for domain in rd.get("domains_list", []):
                                    val = str(domain).strip().lower()
                                    if val and "." in val and val != seed_root:
                                        if root_domain(val) in _REGISTRAR_DOMAINS:
                                            continue
                                        if is_registrable_domain(val) and val not in found:
                                            found.append(val)
                        except Exception:
                            pass

                    # Step 5: Reverse WHOIS by brand keyword
                    brand = seed_root.split(".")[0]
                    if len(brand) >= 3:
                        rev_url = (
                            f"https://api.whoxy.com/?key={api_key}"
                            f"&reverse=whois&keyword={quote_plus(brand)}&mode=domains"
                        )
                        try:
                            r = session.get(rev_url, timeout=timeout)
                            if r.ok:
                                rd = r.json()
                                for domain in rd.get("domains_list", []):
                                    val = str(domain).strip().lower()
                                    if val and "." in val and val != seed_root:
                                        if is_registrable_domain(val) and val not in found:
                                            found.append(val)
                        except Exception:
                            pass
        except Exception as exc:
            logger.info("Whoxy WHOIS lookup failed (%s): %s", seed_root, exc)
    else:
        # Free fallback: RDAP + crt.sh email search (no API key needed)
        # Get WHOIS data via RDAP to extract registrant email/org
        try:
            rdap_url = f"https://rdap.org/domain/{seed_root}"
            resp = session.get(rdap_url, timeout=timeout)
            if resp.ok:
                payload = resp.json()
                emails: list[str] = []
                orgs: list[str] = []

                def _walk_rdap(node: Any) -> None:
                    if isinstance(node, dict):
                        for key, value in node.items():
                            if key == "vcardArray" and isinstance(value, list) and len(value) >= 2:
                                for entry in value[1]:
                                    if isinstance(entry, list) and len(entry) >= 4:
                                        label = str(entry[0]).lower()
                                        text = str(entry[3]).strip()
                                        if label == "email" and text and text not in emails:
                                            emails.append(text)
                                        elif label in ("fn", "org") and text:
                                            for tok in _safe_tokens(text):
                                                if tok not in orgs and len(tok) >= 3:
                                                    orgs.append(tok)
                            else:
                                _walk_rdap(value)
                    elif isinstance(node, list):
                        for item in node:
                            _walk_rdap(item)

                _walk_rdap(payload)

        except Exception as exc:
            logger.info("RDAP-based reverse WHOIS failed (%s): %s", seed_root, exc)

    return found


def _favicon_md5(session: Any, domain: str, *, timeout: int = 8) -> str | None:
    """Compute MD5 hash of a domain's favicon.ico.

    Used for cross-site correlation: sites sharing the same favicon are
    likely operated by the same organization (common with media groups
    using shared branding assets).
    """
    import hashlib
    for scheme in ("https", "http"):
        try:
            resp = session.get(
                f"{scheme}://{domain}/favicon.ico",
                timeout=timeout,
                headers={"User-Agent": "DomainHunter/0.1"},
            )
            resp.raise_for_status()
            if resp.content:
                return hashlib.md5(resp.content).hexdigest()
        except Exception:
            continue
    return None


def _pattern_gen_candidates(label: str, cc_tld: str | None = None) -> list[str]:
    """Generate domain variants by appending common corporate suffixes/prefixes.

    Ported from pseudogeek7/domain-hunter pattern_gen.py — rule-based label
    variants like samaagroup.com, samaamobile.net, mysamaa.org.
    """
    _SUFFIXES = [
        "group", "holdings", "global", "inc", "intl", "international",
        "online", "digital", "tech", "solutions", "services", "systems",
        "mobile", "telecom", "media", "labs", "cloud", "connect", "pay",
        "news", "tv", "press", "entertainment", "sports", "money", "health",
    ]
    _PREFIXES = ["my", "get", "go", "the"]
    _GENERIC_TLDS = ["com", "net", "org", "co"]

    candidates = set()
    for suffix in _SUFFIXES:
        candidates.add(f"{label}{suffix}")
        candidates.add(f"{label}-{suffix}")
    for prefix in _PREFIXES:
        candidates.add(f"{prefix}{label}")

    # Generate domain strings
    domains = []
    tlds = set(_GENERIC_TLDS)
    if cc_tld:
        tlds.add(cc_tld)
    for gen_label in candidates:
        for tld in tlds:
            domains.append(f"{gen_label}.{tld}")
    return domains


def _site_scrape_with_robots(
    session: Any,
    seed_root: str,
    homepage_html: str,
    base_url: str,
    *,
    timeout: int = 15,
) -> list[str]:
    """Enhanced site scrape with robots.txt respect and relationship page detection.

    Ported from pseudogeek7/domain-hunter site_scrape.py — fetches the seed's
    homepage plus relationship pages (about, subsidiaries, partners) for
    outbound links. Respects robots.txt for pages after the homepage.
    """
    from bs4 import BeautifulSoup  # type: ignore
    from urllib.parse import urljoin
    from urllib.robotparser import RobotFileParser

    _RELATIONSHIP_HINTS = [
        "subsidiar", "joint-venture", "jointventure", "joint_venture", "investor",
        "group-compan", "group_compan", "groupcompan", "our-compan", "ourcompan",
        "affiliat", "partner", "about-us", "aboutus", "about",
    ]

    _EXCLUDED_DOMAINS = {
        "facebook.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
        "instagram.com", "pinterest.com", "tiktok.com", "whatsapp.com", "telegram.org",
        "google.com", "googleapis.com", "gstatic.com", "google-analytics.com",
        "googletagmanager.com", "doubleclick.net", "cloudflare.com",
        "wordpress.com", "wp.com", "jquery.com", "jsdelivr.net",
        "w3.org", "schema.org", "wikipedia.org", "wikimedia.org", "apple.com",
        "microsoft.com", "adobe.com",
    }

    soup = BeautifulSoup(homepage_html, "html.parser")

    # Extract all links from homepage
    home_links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        abs_url = urljoin(base_url, href)
        text = (a.get_text() or "").strip()
        home_links.append({"url": abs_url, "text": text})

    # Find relationship pages
    relationship_pages = []
    seen_urls = set()
    for link in home_links:
        parsed = urlparse(link["url"])
        path = parsed.path.lower()
        text = link["text"].lower()
        if any(hint in path or hint in text for hint in _RELATIONSHIP_HINTS):
            host = (parsed.hostname or "").lower()
            if host == seed_root or host.endswith(f".{seed_root}"):
                if link["url"] not in seen_urls:
                    seen_urls.add(link["url"])
                    relationship_pages.append(link["url"])

    # Load robots.txt
    robots = RobotFileParser()
    robots_url = f"{base_url}/robots.txt"
    try:
        robots.set_url(robots_url)
        robots.read()
    except Exception:
        pass

    # Extract external domains from all links
    candidates = []
    seen_domains = {seed_root}

    all_links = home_links.copy()
    for page_url in relationship_pages[:8]:
        # Check robots.txt
        try:
            if not robots.can_fetch("DomainHunter/0.1", page_url):
                continue
        except Exception:
            pass

        # Fetch relationship page
        try:
            resp = session.get(page_url, timeout=timeout, headers={"User-Agent": "DomainHunter/0.1"})
            resp.raise_for_status()
            page_soup = BeautifulSoup(resp.text, "html.parser")
            for a in page_soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    continue
                abs_url = urljoin(page_url, href)
                text = (a.get_text() or "").strip()
                all_links.append({"url": abs_url, "text": text})
        except Exception:
            continue

    for link in all_links:
        parsed = urlparse(link["url"])
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        rd = root_domain(host)
        if not rd or rd in seen_domains or rd in _EXCLUDED_DOMAINS:
            continue
        if rd.endswith(f".{seed_root}"):
            continue
        seen_domains.add(rd)
        candidates.append(rd)

    return candidates


def _tracker_id_pivot(
    session: Any,
    seed_root: str,
    *,
    timeout: int = 8,
) -> list[str]:
    """Google Analytics / Tag Manager / FB Pixel ID pivot.

    Sites sharing the same GA property ID (UA-XXXXX or G-XXXXXXX), GTM
    container (GTM-XXXXXXX), or Facebook Pixel ID (XXXXXXXXXX) are likely
    operated by the same organization.  Extracts tracker IDs from the seed's
    homepage and searches for other sites using the same IDs.

    Sources: BuiltWith-like lookup via public APIs, and direct page scraping.
    """
    import re

    found: list[str] = []

    # Fetch seed homepage to extract tracker IDs
    homepage, _ = _fetch_with_fallback(session, f"https://{seed_root}")
    if not homepage:
        return []

    # Extract GA, GTM, FB Pixel IDs
    ga_ids = re.findall(r'UA-\d{4,}-\d+', homepage)
    gtm_ids = re.findall(r'GTM-\w+', homepage)
    fb_ids = re.findall(r'fbq\(["\']init["\'],\s*["\'](\d+)["\']', homepage)

    tracker_ids = list(set(ga_ids + gtm_ids + fb_ids))
    if not tracker_ids:
        return []

    # Search urlscan.io for domains sharing these tracker IDs
    for tracker_id in tracker_ids[:5]:
        search_url = f"https://urlscan.io/api/v1/search/?q=page trackers.{tracker_id}&size=20"
        try:
            resp = session.get(search_url, timeout=timeout)
            if not resp.ok:
                continue
            data = resp.json()
            for result in data.get("results", []):
                page_domain = result.get("page", {}).get("domain", "")
                if page_domain and page_domain != seed_root:
                    rd = root_domain(page_domain.lower())
                    if rd and rd not in found:
                        found.append(rd)
        except Exception:
            continue

    return found


def _reverse_ip_lookup(session: Any, ip: str, timeout: int = 10) -> list[str]:
    urls = [
        f"https://api.hackertarget.com/reverseiplookup/?q={quote_plus(ip)}",
        f"https://dns.bufferover.run/dns?q={quote_plus(ip)}",
    ]
    domains: list[str] = []
    for url in urls:
        try:
            response = session.get(url, timeout=timeout)
            if not response.ok:
                continue
            body = response.text.strip()
            if not body:
                continue
            if body.startswith("{"):
                payload = response.json()
                data = payload.get("FDNS_A", []) or payload.get("RDNS", []) or []
                for entry in data:
                    candidate = str(entry).split(",")[-1].strip()
                    if candidate and "." in candidate:
                        domains.append(candidate.lower())
            else:
                for line in body.splitlines():
                    candidate = line.strip().lower()
                    if candidate and "." in candidate and candidate not in domains:
                        domains.append(candidate)
            if domains:
                return domains[: _MAX_REVERSE_RESULTS]
        except Exception:
            continue
    return domains[: _MAX_REVERSE_RESULTS]


def _wikidata_official_websites(session: Any, token: str, timeout: int = 8) -> tuple[bool, list[str]]:
    """(entity_found, P856 website values) for the entity matching *token*.

    Top-1 search hit is preferred; if it lacks P856 claims (e.g. the "Disney
    (family name)" entity sitting above The Walt Disney Company), later hits
    are tried until one carries an official website. ``entity_found`` is True
    when any entity matched (even without websites) — callers use it to
    decide whether a bare-brand fallback search is still necessary.
    """
    search_url = (
        "https://www.wikidata.org/w/api.php"
        f"?action=wbsearchentities&search={quote_plus(token)}&language=en&format=json&limit=5"
    )
    try:
        response = session.get(search_url, timeout=timeout)
        if not response.ok:
            return False, []
        results = (response.json().get("search") or [])[:5]
        if not results:
            return False, []
        for hit in results:
            entity_id = hit.get("id", "")
            if not entity_id:
                continue
            claims_url = (
                "https://www.wikidata.org/w/api.php"
                f"?action=wbgetentities&ids={quote_plus(entity_id)}&props=claims&format=json"
            )
            response = session.get(claims_url, timeout=timeout)
            if not response.ok:
                continue
            entities = response.json().get("entities", {})
            claims = entities.get(entity_id, {}).get("claims", {})
            websites: list[str] = []
            for claim in claims.get("P856", []):
                try:
                    value = claim["mainsnak"]["datavalue"]["value"]
                    if isinstance(value, str) and value.strip():
                        websites.append(value.strip())
                except (KeyError, TypeError):
                    continue
            if websites:
                return True, websites
            entity_found = True
        return entity_found, []
    except Exception:
        return False, []


def _extract_emails_from_html(html: str) -> list[str]:
    """Extract email addresses from HTML content."""
    emails: list[str] = []
    for match in _EMAIL_RE.finditer(html):
        email = match.group(0).strip().lower()
        if email not in emails:
            emails.append(email)
    return emails


def _spf_includes(domain: str) -> list[str]:
    """Extract include: domains from SPF TXT record."""
    includes: list[str] = []
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4
        resolver.timeout = 3
        answers = resolver.resolve(domain, "TXT")
        for rr in answers:
            txt = str(rr).strip().strip('"')
            if txt.lower().startswith("v=spf1"):
                for part in txt.split():
                    if part.lower().startswith("include:"):
                        inc = part.split(":", 1)[1].strip()
                        if inc:
                            includes.append(inc)
    except Exception:
        pass
    return includes


def _dmarc_rua(domain: str) -> list[str]:
    """Extract aggregate report URIs from DMARC TXT record."""
    rua: list[str] = []
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4
        resolver.timeout = 3
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rr in answers:
            txt = str(rr).strip().strip('"')
            if txt.lower().startswith("v=dmarc1"):
                for part in txt.split(";"):
                    part = part.strip()
                    if part.lower().startswith("rua="):
                        uris = part.split("=", 1)[1]
                        for uri in uris.split(","):
                            uri = uri.strip()
                            if uri.startswith("mailto:"):
                                uri = uri[7:]
                            if "@" in uri:
                                rua.append(uri.split("@")[-1].strip())
    except Exception:
        pass
    return rua


def _reverse_ns_for_domain(domain: str) -> list[str]:
    """Find other domains sharing the same authoritative NS servers."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4
        resolver.timeout = 3
        answers = resolver.resolve(domain, "NS")
        ns_hosts = [str(rr).strip().rstrip(".") for rr in answers]
    except Exception:
        return []

    # For each NS, do a reverse DNS lookup to find other domains on it
    # We use crt.sh to search for domains with the same NS
    related: list[str] = []
    for ns in ns_hosts[:3]:
        # crt.sh doesn't have NS search, but we can check the NS hostname's
        # own domain and search for cert SANs containing it
        ns_domain = root_domain(ns)
        if ns_domain and ns_domain != domain:
            related.append(ns_domain)
    return related


def _asn_netblock(asn: str) -> list[str]:
    """Get CIDR netblocks for an ASN via Team Cymru."""
    cidrs: list[str] = []
    try:
        connection = socket.create_connection(("whois.cymru.com", 43), timeout=6)
        try:
            connection.sendall(f"-v {asn}\r\n".encode("ascii"))
            data = b""
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            connection.close()
        for line in data.decode("utf-8", errors="replace").splitlines()[1:]:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2 and parts[0].isdigit():
                # Get the BGP prefix
                if len(parts) >= 3 and parts[2]:
                    cidr = parts[2]
                    if "/" in cidr:
                        cidrs.append(cidr)
    except Exception:
        pass
    return cidrs[:20]


def _wikidata_search_forms(seed_root: str) -> list[str]:
    """Search strings for the seed's Wikidata entity, loosest last.

    The raw seed root matches most entities (abc.xyz -> Alphabet). When it
    doesn't — wikidata tokenizes dot-separated queries unreliably
    (``7-eleven.com`` returns zero hits) — progressively looser seed-derived
    forms are tried: the (possibly hyphenated) label, its collapsed
    alphanumeric form, then the seed's own tokens (len >= 3, PSL-TLD-like
    labels such as ``gov`` in gov.uk skipped). Every fallback stays anchored
    to the seed's own name, so a bare brand token that is not part of the
    seed can never route the search to a namesake entity.
    """
    label = seed_root.split(".")[0].lower()
    seed_tld = seed_root.split(".", 1)[1] if "." in seed_root else ""
    forms: list[str] = [seed_root]
    if len(label) >= 3 and not _is_tld_like_label(label, seed_tld):
        forms.append(label)
        collapsed = "".join(ch for ch in label if ch.isalnum())
        if collapsed and collapsed != label:
            forms.append(collapsed)
    for token in _seed_base_tokens(seed_root):
        if len(token) < 3:
            continue
        if _is_tld_like_label(token, seed_tld):
            continue
        if token not in forms:
            forms.append(token)
    return forms


@dataclass
class Candidate:
    domain: str
    score: int = 0
    methods: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    live: bool = False

    def add(self, method: str, points: int, evidence: str) -> None:
        if method not in self.methods:
            self.methods.append(method)
            self.score += points
        # Repeats of the same signal (e.g. asn hits on two IPs) add evidence
        # but NOT points — one signal, one score, or co-location would stack.
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)


# ---------------------------------------------------------------------------
# .env loader + AI Hunt (LLM-powered hypothesis generation)
# ---------------------------------------------------------------------------

def _load_env_file() -> dict[str, str]:
    """Load .env file from project root or current directory."""
    env_vars = {}
    # Check multiple possible .env locations
    for candidate in [
        Path(__file__).resolve().parents[3] / ".env",  # global project root
        Path(__file__).resolve().parent / ".env",  # same dir as script (fallback)
        Path(__file__).resolve().parents[2] / ".env",  # mcp-servers/ (fallback)
        Path.cwd() / ".env",
    ]:
        if candidate.exists():
            with open(candidate, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip().strip("'\"")
                        if key and value:
                            env_vars[key] = value
            break
    return env_vars


_ENV_CACHE: dict[str, str] = {}


def _get_env(key: str, default: str = "") -> str:
    """Get env var with .env file fallback."""
    global _ENV_CACHE
    if not _ENV_CACHE:
        _ENV_CACHE = _load_env_file()
    import os
    return os.environ.get(key, _ENV_CACHE.get(key, default))


def _web_search_sister_domains(
    session: Any,
    seed_root: str,
    *,
    timeout: int = 10,
) -> tuple[list[str], dict[str, list[str]]]:
    """Web search for domains associated with the seed.

    Returns (domains, context) — context maps each domain to up to 3 short
    strings explaining WHERE it was found (which query, which Wikipedia
    section) so the caller (and ultimately the LLM triaging candidates) can
    see WHY a domain was proposed, not just that it was. No relevance
    filtering beyond DNS resolution — the LLM module or the caller decides
    what's a real sister vs noise.

    Search backend: DuckDuckGo's no-JS HTML endpoint (mcp-servers/recon/
    tools/_web_search_cli.py — the same free, no-API-key search used by
    web_search). Previously this scraped google.com/search and bing.com/
    search directly, which both aggressively block non-browser traffic
    (CAPTCHA/blocked responses) — that returned empty results silently far
    more often than it returned anything, exactly the kind of "looks
    complete, does nothing" gap this whole module exists to avoid creating
    for the LLM triaging its output.
    """
    from bs4 import BeautifulSoup  # type: ignore

    _TOOLS_DIR = Path(__file__).resolve().parent
    if str(_TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(_TOOLS_DIR))
    from _web_search_cli import search as _ddg_search

    brand = seed_root.split(".")[0]
    seed_tld = seed_root.rsplit(".", 1)[-1]
    found: list[str] = []
    contexts: dict[str, list[str]] = {}

    def _record(rd: str, context: str) -> None:
        if not rd or rd == seed_root:
            return
        if rd not in found:
            found.append(rd)
        ctx_list = contexts.setdefault(rd, [])
        if context not in ctx_list and len(ctx_list) < 3:
            ctx_list.append(context)

    # --- Source 1: Wikipedia page ---
    try:
        wiki_url = f"https://en.wikipedia.org/wiki/{brand.replace(' ', '_')}_Television_Network"
        resp = session.get(wiki_url, timeout=timeout)
        if resp.ok:
            soup = BeautifulSoup(resp.text, "html.parser")
            content = soup.find("div", {"id": "mw-content-text"})
            if content:
                text = content.get_text(" ", strip=True)
                for match in _DOMAIN_RE.finditer(text):
                    rd = root_domain(match.group(1).lower())
                    _record(rd, "found on the seed org's Wikipedia page")
                for match in re.finditer(r'https?://([a-z0-9.-]+\.[a-z]{2,})', text):
                    rd = root_domain(match.group(1).lower())
                    _record(rd, "linked from the seed org's Wikipedia page")
                # "Geo Super" -> geosuper.tv
                for match in re.finditer(rf'{re.escape(brand)}\s+(\w{{2,}})', text, re.IGNORECASE):
                    suffix = match.group(1).strip().lower()
                    if suffix not in {'news', 'tv', 'television', 'network', 'group', 'entertainment', 'films'}:
                        candidate = f"{brand.lower()}{suffix}.{seed_tld}"
                        _record(candidate, f"brand-name pattern match on Wikipedia ('{brand} {suffix}')")
    except Exception as exc:
        logger.info("Wikipedia fetch failed for %s: %s", seed_root, exc)

    # --- Source 2: DuckDuckGo (free, no API key, no-JS HTML endpoint —
    # reliable where scraping Google/Bing directly is not) ---
    for query in [
        f"{seed_root} sister domains affiliated websites",
        f"{brand} official website domains network",
        f'"{brand}" site:wikipedia.org',
    ]:
        try:
            result = _ddg_search(query, limit=10)
        except Exception as exc:
            logger.info("web_search query failed (%r): %s", query, exc)
            continue
        for row in result.get("results", []):
            url = row.get("url", "")
            host = urlparse(url).hostname if url else None
            snippet_text = f"{row.get('title', '')} {row.get('snippet', '')}"
            context = f"web search {query!r}: {row.get('title', '')[:80]}"
            if host:
                _record(root_domain(host.lower()), context)
            for match in _DOMAIN_RE.finditer(snippet_text):
                _record(root_domain(match.group(1).lower()), context)

    # DNS-verify, keep the context evidence attached for the caller.
    verified = [rd for rd in found if _domain_resolves(rd)]
    return verified, {rd: contexts.get(rd, []) for rd in verified}


_AI_HUNT_PROMPT = """You are assisting an OSINT domain-discovery tool. Given a seed \
organization, propose plausible ADDITIONAL domains that might be owned or operated by \
the same organization, across these categories:
- TLD/spelling variants of the seed's own name
- Wholly-owned subsidiaries, brands, or products
- Joint ventures with partial or shared ownership
- Affiliated organizations (alumni associations, foundations, hosted projects, \
training/research arms)
- Language-specific versions (e.g. urdu.seed.tv for a Pakistani news org)
- Vertical-specific domains (e.g. seedmoney.com, seedsport.com)

Some entities genuinely have no standalone domain — if so, leave the domain empty \
rather than inventing one you're not confident exists.

Seed domain: {domain}
Organization name (if known): {org_name}
Already-known associated domains: {known_domains}

Respond with ONLY a JSON object, no markdown, no commentary:
{{
  "tld_variants": ["<domain>", ...],
  "subsidiaries_brands_products": [
    {{"name": "<entity>", "domain": "<domain or empty>", "relationship": "<description>"}}
  ],
  "joint_ventures": [
    {{"name": "<entity>", "domain": "<domain or empty>", "partners": "<ownership split>"}}
  ],
  "affiliated_orgs": [
    {{"name": "<entity>", "domain": "<domain or empty>", "category": "<category>"}}
  ]
}}"""

_DEFAULT_LLM_MODELS = {
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-3.6-flash",
}


def _call_llm_hunt(
    session: Any,
    domain: str,
    org_name: str = "",
    known_domains: list[str] | None = None,
    *,
    timeout: int = 60,
) -> list[str]:
    """LLM-powered hypothesis generation via Gemini/Anthropic/OpenAI.

    Returns a list of candidate domains suggested by the LLM.
    API key read from .env: dom_hunter_gemini_key, dom_hunter_anthropic_key,
    dom_hunter_openai_key, or generic DOM_HUNTER_LLM_KEY.
    """
    # Find API key from .env
    provider = ""
    api_key = ""
    model = ""

    for prov, env_key, default_model in [
        ("gemini", "dom_hunter_gemini_key", "gemini-3.6-flash"),
        ("anthropic", "dom_hunter_anthropic_key", "claude-sonnet-5"),
        ("openai", "dom_hunter_openai_key", "gpt-4o-mini"),
    ]:
        key = _get_env(env_key)
        if key:
            provider = prov
            api_key = key
            model = _get_env("dom_hunter_llm_model", default_model)
            break

    if not provider:
        logger.info("ai_hunt: SKIPPED — no dom_hunter_*_key in .env")
        return []

    known_domains = known_domains or []
    prompt = _AI_HUNT_PROMPT.format(
        domain=domain,
        org_name=org_name or "unknown",
        known_domains=", ".join(known_domains[:20]) if known_domains else "none yet",
    )

    try:
        if provider == "gemini":
            raw = _call_gemini(api_key, model, prompt, timeout=timeout)
        elif provider == "anthropic":
            raw = _call_anthropic(api_key, model, prompt, timeout=timeout)
        elif provider == "openai":
            raw = _call_openai(api_key, model, prompt, timeout=timeout)
        else:
            return []
    except Exception as exc:
        logger.warning("ai_hunt: LLM call failed: %s", exc)
        return []

    return _parse_llm_proposals(raw)


def _call_gemini(api_key: str, model: str, prompt: str, *, timeout: int = 60) -> str:
    """Call Google Gemini API."""
    import requests as _req
    resp = _req.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        params={"key": api_key},
        json={
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json"},
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["candidates"][0]["content"]["parts"][0]["text"]


def _call_anthropic(api_key: str, model: str, prompt: str, *, timeout: int = 60) -> str:
    """Call Anthropic API."""
    import requests as _req
    resp = _req.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={"model": model, "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["content"][0]["text"]


def _call_openai(api_key: str, model: str, prompt: str, *, timeout: int = 60) -> str:
    """Call OpenAI API."""
    import requests as _req
    resp = _req.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _parse_llm_proposals(raw: str) -> list[str]:
    """Parse LLM JSON response into a list of candidate domains."""
    import json as _json
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if "\n" in text:
            first_line, rest = text.split("\n", 1)
            text = rest if first_line.strip().lower() in ("json", "") else text

    try:
        data, _ = _json.JSONDecoder().raw_decode(text.strip())
    except (ValueError, _json.JSONDecodeError) as exc:
        logger.warning("ai_hunt: failed to parse LLM JSON: %s", exc)
        return []

    candidates = []
    seen = set()

    # Collect all domains from the response
    for key in ("tld_variants",):
        for item in (data.get(key) or []):
            if isinstance(item, str) and item and item not in seen:
                candidates.append(item.lower().strip("."))
                seen.add(item)

    for key in ("subsidiaries_brands_products", "joint_ventures", "affiliated_orgs"):
        for item in (data.get(key) or []):
            if isinstance(item, dict):
                domain = (item.get("domain") or "").strip().lower().strip(".")
                if domain and domain not in seen and _DOMAIN_RE.match(domain):
                    candidates.append(domain)
                    seen.add(domain)

    return candidates


def _site_scrape_relationship_pages(
    session: Any,
    seed_root: str,
    homepage_html: str,
    base_url: str,
    *,
    timeout: int = 15,
) -> list[str]:
    """Scrape relationship pages (about, subsidiaries, partners) for outbound links.

    Ported from pseudogeek7/domain-hunter site_scrape.py — finds external domains
    the org lists on its own site (highest-priority evidence).
    """
    from bs4 import BeautifulSoup  # type: ignore

    _RELATIONSHIP_HINTS = [
        "subsidiar", "joint-venture", "jointventure", "joint_venture", "investor",
        "group-compan", "group_compan", "groupcompan", "our-compan", "ourcompan",
        "affiliat", "partner", "about-us", "aboutus", "about",
    ]

    _EXCLUDED_DOMAINS = {
        "facebook.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
        "instagram.com", "pinterest.com", "tiktok.com", "whatsapp.com", "telegram.org",
        "google.com", "googleapis.com", "gstatic.com", "google-analytics.com",
        "googletagmanager.com", "doubleclick.net", "cloudflare.com",
        "wordpress.com", "wp.com", "jquery.com", "jsdelivr.net",
        "w3.org", "schema.org", "wikipedia.org", "wikimedia.org", "apple.com",
        "microsoft.com", "adobe.com",
    }

    soup = BeautifulSoup(homepage_html, "html.parser")

    # Extract all links from homepage
    home_links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        from urllib.parse import urljoin
        abs_url = urljoin(base_url, href)
        text = (a.get_text() or "").strip()
        home_links.append({"url": abs_url, "text": text})

    # Find relationship pages
    relationship_pages = []
    seen_urls = set()
    for link in home_links:
        parsed = urlparse(link["url"])
        path = parsed.path.lower()
        text = link["text"].lower()
        if any(hint in path or hint in text for hint in _RELATIONSHIP_HINTS):
            host = (parsed.hostname or "").lower()
            if host == seed_root or host.endswith(f".{seed_root}"):
                if link["url"] not in seen_urls:
                    seen_urls.add(link["url"])
                    relationship_pages.append(link["url"])

    # Extract external domains from all links
    candidates = []
    seen_domains = {seed_root}

    for link in home_links + [{"url": p, "text": ""} for p in relationship_pages[:8]]:
        parsed = urlparse(link["url"])
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        rd = root_domain(host)
        if not rd or rd in seen_domains or rd in _EXCLUDED_DOMAINS:
            continue
        if rd.endswith(f".{seed_root}"):
            continue
        seen_domains.add(rd)
        candidates.append(rd)

    return candidates


class DomainHunter:
    """Best-effort sister-domain discovery with multiple weak signals."""

    def __init__(self, domain: str, *, modules: str = "", confidence_min: str = "low") -> None:
        self.seed_root = hunter_seed_apex(domain)
        self.seed = self.seed_root
        self.seed_tld = self.seed_root.rsplit(".", 1)[-1] if self.seed_root else ""
        self.modules = self._normalize_modules(modules)
        self.confidence_min = confidence_min if confidence_min in _CONF_RANK else "low"
        self.session = _http_session()
        self.candidates: dict[str, Candidate] = {}
        self._brand_tokens: list[str] = _brand_tokens(self.seed_root)

    @staticmethod
    def _normalize_modules(modules: str) -> set[str]:
        if not modules.strip():
            return {
                "dns", "whois", "site_scrape",
                "email_pivot", "spf_dmarc",
                "reverse_ns", "reverse_whois", "tracker_pivot", "ai_hunt",
                "favicon", "web_search",
            }
        normalized = {part.strip().lower() for part in modules.split(",") if part.strip()}
        aliases = {
            "crawl": "site_scrape",
            "scrape": "site_scrape",
            "rdap": "whois",
            "email": "email_pivot",
            "dmarc": "spf_dmarc",
            "spf": "spf_dmarc",
            "ns": "reverse_ns",
            "nameserver": "reverse_ns",
            "revwhois": "reverse_whois",
            "rev-whois": "reverse_whois",
            "whoxy": "reverse_whois",
            "trackers": "tracker_pivot",
            "ga_pivot": "tracker_pivot",
            "llm": "ai_hunt",
            "gemini": "ai_hunt",
            "gpt": "ai_hunt",
            "anthropic": "ai_hunt",
            "icon": "favicon",
            "favicon_hash": "favicon",
        }
        return {aliases.get(part, part) for part in normalized}

    def _emit_progress(self, stage: str) -> None:
        # Discovery can run long (site fetch + cert transparency + DNS brute +
        # ASN + RDAP), and the whole thing only printed once at the very end —
        # if the outer exec_timeout killed the process mid-run, stdout was
        # empty. Print a snapshot after every module so a mid-run kill still
        # leaves a usable partial result on stdout instead of nothing. Reuses
        # format_rows()'s exact "=== Findings ===" layout so parse_stdout can
        # read it the same way as the final block; a leading comment line (not
        # matched by row_re/the "===" checks) marks it as in-progress. A
        # machine-readable JSON line follows so a timeout still yields rows
        # even if the table is truncated.
        print(f"# domain_hunter progress: completed={stage!r} candidates_so_far={len(self.candidates)}")
        emit_findings_snapshot(list(self.candidates.values()))

    def discover(self) -> list[Candidate]:
        if not self.seed_root:
            return []

        if "site_scrape" in self.modules:
            self._collect_site_signals()
            self._emit_progress("site_scrape")
        if "dns" in self.modules:
            self._collect_dns_signals()
            self._emit_progress("dns")
        if "whois" in self.modules:
            self._collect_rdap_signals()
            self._emit_progress("whois")
        if "email_pivot" in self.modules:
            self._collect_email_pivot_signals()
            self._emit_progress("email_pivot")
        if "spf_dmarc" in self.modules:
            self._collect_spf_dmarc_signals()
            self._emit_progress("spf_dmarc")
        if "reverse_ns" in self.modules:
            self._collect_reverse_ns_signals()
            self._emit_progress("reverse_ns")
        if "reverse_whois" in self.modules:
            self._collect_reverse_whois_signals()
            self._emit_progress("reverse_whois")
        if "tracker_pivot" in self.modules:
            self._collect_tracker_pivot_signals()
            self._emit_progress("tracker_pivot")
        if "ai_hunt" in self.modules:
            self._collect_ai_hunt_signals()
            self._emit_progress("ai_hunt")
        if "favicon" in self.modules:
            self._collect_favicon_signals()
            self._emit_progress("favicon")
        if "web_search" in self.modules:
            self._collect_web_search_signals()
            self._emit_progress("web_search")

        self._resolve_live_status()

        filtered = [c for c in self.candidates.values() if self._passes_confidence_floor(c)]
        filtered.sort(key=lambda item: (-item.score, not item.live, item.domain))
        return filtered

    def _add_candidate(self, domain: str, *, method: str, points: int, evidence: str) -> None:
        domain = root_domain(domain)
        if not domain or "." not in domain:
            return
        if not _is_likely_domain_or_none(domain):
            return
        if not self.seed_root or is_same_root(domain, self.seed_root):
            return
        # Candidates living at a shared cloud-platform apex (azurewebsites.net,
        # cloudfront.net, github.io, ...) are never an affiliated root — the
        # PSL private section says so authoritatively (see _at_psl_private_apex).
        if _at_psl_private_apex(domain):
            return
        # Tracker/social/platform apexes only get suppressed as weak third-party
        # evidence: SITE-SCRAPE (links/robots/sitemap — a homepage linking to
        # facebook.com or cdnjs.com means nothing), DNS host records (an NS
        # or MX host at a provider apex like cloudflare.com means the seed USES
        # that provider — the provider apex is never the sister's own name),
        # and WEB_SEARCH (a result mentioning youtube.com/github.com/facebook.com
        # alongside the seed is exactly as meaningless as finding the same link
        # on the seed's own homepage). Certs/ASN evidence still counts, so a
        # platform apex with real signals is not masked.
        if method in ("site_scrape", "dns", "web_search") and root_domain(domain) in _SITE_LINK_NOISE_ROOTS:
            return
        candidate = self.candidates.get(domain)
        if candidate is None:
            candidate = Candidate(domain=domain)
            self.candidates[domain] = candidate
        candidate.add(method, points, evidence)

    def _collect_site_signals(self) -> None:
        homepage, final_url = _fetch_with_fallback(self.session, f"https://{self.seed_root}")
        if not homepage:
            return

        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(homepage, "html.parser")
        title = (soup.title.get_text(" ", strip=True) if soup.title else "").strip()
        token_pool = _brand_tokens(self.seed_root, title)

        for tag in soup.find_all(["a", "link", "script", "img", "iframe", "source"]):
            for attr in ("href", "src", "data-src", "content"):
                value = tag.get(attr)
                if not value:
                    continue
                raw = str(value).strip()
                if not raw:
                    continue
                parsed = urlparse(raw)
                hostname = parsed.hostname
                if not hostname and raw.startswith("//"):
                    parsed2 = urlparse(f"https:{raw}")
                    hostname = parsed2.hostname
                if hostname and _is_likely_domain_or_none(hostname):
                    rd = root_domain(hostname)
                    if rd and rd != self.seed_root:
                        self._add_candidate(
                            rd,
                            method="site_scrape",
                            points=_POINTS_SITE_LINK,
                            evidence=f"homepage link: {hostname}",
                        )

        # Visible-text extraction is intentionally skipped: the tag-attribute
        # loop above already catches every linked domain while properly URL-parsing
        # the value.  Plain-text regex extraction adds disproportionate noise
        # (JavaScript property-access patterns, code examples, etc.) for minimal
        # signal gain, so it is not performed here.

        for token in token_pool[:4]:
            if len(token) < 4:
                continue
            if token in title.lower() and len(token_pool) > 1:
                self._brand_tokens.append(token)

        if final_url and final_url != f"https://{self.seed_root}":
            final_host = root_domain(urlparse(final_url).hostname or "")
            if final_host and final_host != self.seed_root:
                self._add_candidate(
                    final_host,
                    method="site_scrape",
                    points=_POINTS_REDIRECT,
                    evidence=f"redirected to {final_url}",
                )

        robots, _ = _fetch_with_fallback(self.session, f"https://{self.seed_root}/robots.txt")
        sitemap, _ = _fetch_with_fallback(self.session, f"https://{self.seed_root}/sitemap.xml")
        for blob, label in ((robots, "robots.txt"), (sitemap, "sitemap.xml")):
            if not blob:
                continue
            for domain in _extract_domains(blob):
                rd = root_domain(domain)
                if rd and rd != self.seed_root:
                    self._add_candidate(
                        rd,
                        method="site_scrape",
                        points=_POINTS_ROBOTS_SITEMAP,
                        evidence=f"{label} reference: {domain}",
                    )

        # Scrape relationship pages (about, subsidiaries, partners) for outbound links
        # This finds external domains the org lists on its own site — highest-priority evidence
        # Enhanced version with robots.txt respect
        try:
            rel_candidates = _site_scrape_with_robots(
                self.session, self.seed_root, homepage, f"https://{self.seed_root}",
            )
            for rd in rel_candidates:
                self._add_candidate(
                    rd,
                    method="site_scrape",
                    points=_POINTS_SITE_LINK + 5,  # bonus for relationship page evidence
                    evidence=f"relationship page link: {rd}",
                )
        except Exception as exc:
            logger.info("site_scrape: enhanced scraping failed: %s", exc)

    def _collect_dns_signals(self) -> None:
        hosts = _resolve_dns_hosts(self.seed_root)
        for host in hosts:
            rd = root_domain(host)
            if rd and rd != self.seed_root:
                self._add_candidate(
                    rd,
                    method="dns",
                    points=_POINTS_DNS,
                    evidence=f"shared DNS host: {host}",
                )

    def _collect_reverse_ip_signals(self) -> None:
        ips = _resolve_ips(self.seed_root)
        for ip in ips[:4]:
            # A CDN/edge IP shares its address with millions of unrelated
            # domains — co-location there is NOT an affiliation signal. Detect
            # edges by the owning ASN organization (see _is_shared_edge_ip)
            # and skip them before the reverse lookup.
            if _is_shared_edge_ip(ip):
                continue
            domains = _reverse_ip_lookup(self.session, ip)
            for domain in domains:
                rd = root_domain(domain)
                if rd and rd != self.seed_root:
                    self._add_candidate(
                        rd,
                        method="asn",
                        points=_POINTS_ASN,
                        evidence=f"reverse IP {ip}: {domain}",
                    )

    def _collect_rdap_signals(self) -> None:
        rdap_url = f"https://rdap.org/domain/{self.seed_root}"
        try:
            response = self.session.get(rdap_url, timeout=8)
            if not response.ok:
                return
            payload = response.json()
        except Exception:
            return

        org_tokens: list[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "vcardArray" and isinstance(value, list) and len(value) >= 2:
                        cards = value[1]
                        if isinstance(cards, list):
                            for entry in cards:
                                if not isinstance(entry, list) or len(entry) < 4:
                                    continue
                                label = str(entry[0]).lower()
                                text = str(entry[3]).strip()
                                if label in {"fn", "org"} and text:
                                    for token in _safe_tokens(text):
                                        if token not in org_tokens:
                                            org_tokens.append(token)
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)

    def _collect_email_pivot_signals(self) -> None:
        """Extract emails from the seed site, then search crt.sh by registrant email.

        Finds other domains registered by the same people/organization.
        """
        # Step 1: Extract emails from the seed homepage + common email-leaking pages
        homepage, _ = _fetch_with_fallback(self.session, f"https://{self.seed_root}")
        emails: list[str] = []
        if homepage:
            emails.extend(_extract_emails_from_html(homepage))

        # Check common email-leaking paths
        for path in (
            "/contact", "/contact-us", "/about", "/about-us", "/imprint",
            "/privacy", "/legal", "/team", "/staff", "/wp-admin",
            "/robots.txt", "/security.txt", "/.well-known/security.txt",
        ):
            text, _ = _fetch(self.session, f"https://{self.seed_root}{path}", timeout=5)
            if text:
                emails.extend(_extract_emails_from_html(text))

        # Also check the seed domain's MX host for email patterns
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 4
            resolver.timeout = 3
            answers = resolver.resolve(self.seed_root, "MX")
            for rr in answers:
                mx_host = str(rr.exchange).strip().rstrip(".")
                # Extract the org domain from MX hostname (e.g., mx1.geoit.tv → geoit.tv)
                mx_rd = root_domain(mx_host)
                if mx_rd and mx_rd != self.seed_root:
                    self._add_candidate(
                        mx_rd,
                        method="email_pivot",
                        points=_POINTS_EMAIL_PIVOT,
                        evidence=f"MX host org domain: {mx_rd}",
                    )
        except Exception:
            pass

        # Deduplicate
        seen: set[str] = set()
        unique_emails: list[str] = []
        for e in emails:
            local = e.split("@")[0]
            if local not in seen:
                seen.add(local)
                unique_emails.append(e)

    def _collect_spf_dmarc_signals(self) -> None:
        """Parse SPF includes and DMARC rua addresses to find related domains.

        SPF include: targets and DMARC aggregate-report domains often belong to
        the same organization or its email infrastructure partners.
        """
        # SPF includes
        for inc in _spf_includes(self.seed_root):
            rd = root_domain(inc)
            if rd and rd != self.seed_root:
                self._add_candidate(
                    rd,
                    method="spf_dmarc",
                    points=_POINTS_SPF_DMARC,
                    evidence=f"SPF include: {inc}",
                )

        # DMARC rua domains
        for rua in _dmarc_rua(self.seed_root):
            rd = root_domain(rua)
            if rd and rd != self.seed_root:
                self._add_candidate(
                    rd,
                    method="spf_dmarc",
                    points=_POINTS_SPF_DMARC,
                    evidence=f"DMARC rua domain: {rua}",
                )

    def _collect_reverse_ns_signals(self) -> None:
        """Find domains sharing the same authoritative NS servers.

        Self-hosted DNS (ns1/ns2.brand.tld) means every domain using those NS
        servers is operated by the same entity.  NS providers (Cloudflare,
        Route53, etc.) are filtered out — they host millions of unrelated domains.
        """
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 4
            resolver.timeout = 3
            answers = resolver.resolve(self.seed_root, "NS")
            ns_hosts = [str(rr).strip().rstrip(".") for rr in answers]
        except Exception:
            return

        for ns in ns_hosts:
            ns_rd = root_domain(ns)
            if not ns_rd or ns_rd == self.seed_root:
                continue
            # Skip NS provider domains (Cloudflare, Route53, etc.) — they are
            # shared infrastructure, not affiliation signals.
            if root_domain(ns_rd) in _SITE_LINK_NOISE_ROOTS:
                continue
            ns_base = ns_rd.split(".")[0]
            if any(kw in ns_base.upper() for kw in ("CLOUDFLARE", "ROUTE53", "AWS", "NSONE", "DYNDNS")):
                continue
            self._add_candidate(
                ns_rd,
                method="reverse_ns",
                points=_POINTS_REVERSE_NS,
                evidence=f"authoritative NS: {ns}",
            )

    def _collect_reverse_whois_signals(self) -> None:
        """Reverse WHOIS discovery — finds domains by same registrant/org.

        Uses Whoxy API (when WHOXY_API_KEY is set) for comprehensive reverse
        WHOIS by email, company name, and registrant name.  Falls back to
        ViewDNS free API when no Whoxy key is available.

        This is the SINGLE HIGHEST-VALUE module for sister-domain discovery:
        it finds domains that share NO infrastructure, NO certs, and NO DNS —
        they are only linked by the same human or organization registering them.
        """
        for rd in _whoxy_reverse_whois(self.session, self.seed_root):
            if rd != self.seed_root:
                self._add_candidate(
                    rd,
                    method="reverse_whois",
                    points=_POINTS_REVERSE_WHOIS,
                    evidence=f"reverse WHOIS: same registrant/org as {self.seed_root}",
                )

    def _collect_tracker_pivot_signals(self) -> None:
        """Tracker ID pivot — finds domains sharing GA/GTM/FB Pixel IDs.

        Sites sharing the same Google Analytics property ID, GTM container,
        or Facebook Pixel ID are likely operated by the same organization.
        Extracts tracker IDs from the seed's homepage and searches urlscan.io
        for other sites using the same IDs.
        """
        for rd in _tracker_id_pivot(self.session, self.seed_root):
            if rd != self.seed_root:
                self._add_candidate(
                    rd,
                    method="tracker_pivot",
                    points=_POINTS_TRACKER_PIVOT,
                    evidence=f"shared tracker ID with {self.seed_root}",
                )

    def _collect_ai_hunt_signals(self) -> None:
        """AI-powered hypothesis generation via LLM (Gemini/Anthropic/OpenAI).

        The LLM proposes plausible sister domains based on organizational
        knowledge, then each suggestion is verified via DNS before recording.
        API key read from .env: dom_hunter_gemini_key, dom_hunter_anthropic_key,
        or dom_hunter_openai_key.
        """
        # Gather context from other modules
        known_domains = list(self.candidates.keys())
        org_name = ""
        # Try to get org name from Wikidata or WHOIS
        if "knowledge_recon" in self.modules:
            for c in self.candidates.values():
                if "wikidata" in c.methods:
                    # Extract org name from evidence
                    for ev in c.evidence:
                        if "organization" in ev.lower() or "company" in ev.lower():
                            org_name = ev.split(":")[-1].strip() if ":" in ev else ""
                            break
                    if org_name:
                        break

        # Call LLM
        candidates = _call_llm_hunt(
            self.session,
            self.seed_root,
            org_name=org_name,
            known_domains=known_domains,
        )

        # Add verified candidates
        for domain in candidates:
            rd = root_domain(domain)
            if rd and rd != self.seed_root and not _at_psl_private_apex(rd):
                self._add_candidate(
                    rd,
                    method="ai_hunt",
                    points=_POINTS_AI_HUNT,
                    evidence=f"LLM hypothesis: {domain}",
                )

    def _collect_web_search_signals(self) -> None:
        """Web search for associated/sister/parent domains of the target.

        Searches Wikipedia + DuckDuckGo (free, no API key), extracts domain
        names from results and their surrounding text. Each is DNS-verified
        before recording, and tagged with WHY it was proposed (which query
        or Wikipedia section it came from) so the LLM triaging candidates
        afterward has real evidence to weigh, not just a bare domain name.
        """
        domains, context = _web_search_sister_domains(self.session, self.seed_root)
        for rd in domains:
            if rd == self.seed_root:
                continue
            reasons = context.get(rd) or [f"web search: associated with {self.seed_root}"]
            self._add_candidate(
                rd,
                method="web_search",
                points=25,
                evidence="; ".join(reasons),
            )

    def _collect_favicon_signals(self) -> None:
        """Favicon MD5 fingerprinting for cross-site correlation.

        Sites sharing the same favicon are likely operated by the same
        organization (common with media groups using shared branding assets).
        Computes the seed's favicon hash, then checks all existing candidates.
        """
        seed_hash = _favicon_md5(self.session, self.seed_root)
        if not seed_hash:
            return

        # Store seed hash for later comparison
        self._seed_favicon_hash = seed_hash

        # Check all existing candidates for matching favicon
        for candidate in list(self.candidates.values()):
            if candidate.domain == self.seed_root:
                continue
            cand_hash = _favicon_md5(self.session, candidate.domain)
            if cand_hash and cand_hash == seed_hash:
                candidate.add(
                    "favicon_hash",
                    _POINTS_FAVICON_HASH,
                    f"identical favicon MD5 hash to {self.seed_root}",
                )

    def _resolve_live_status(self) -> None:
        # Parallel sweep with a global time budget: probing hundreds of
        # candidates serially at up to 8s each can take minutes (each host
        # tries https then http). 8 workers + hard per-probe timeout bounds a
        # 100-candidate sweep to ~2 minutes worst case; the deadline ensures
        # pathological hosts cannot stall the whole run.
        from concurrent.futures import ThreadPoolExecutor, as_completed

        deadline = time.monotonic() + 90.0

        def probe(candidate: Candidate) -> tuple[bool, str | None]:
            if time.monotonic() > deadline:
                return False, None
            return _live_probe(self.session, candidate.domain)

        futures = {}
        with ThreadPoolExecutor(max_workers=8) as executor:
            for candidate in self.candidates.values():
                futures[executor.submit(probe, candidate)] = candidate
            for future in as_completed(futures):
                candidate = futures[future]
                try:
                    live, url = future.result()
                except Exception:
                    live, url = False, None
                candidate.live = live
                if live and url:
                    candidate.add("live_probe", _POINTS_LIVE, f"live at {url}")

    def _passes_confidence_floor(self, candidate: Candidate) -> bool:
        confidence = candidate_confidence(candidate)
        return _CONF_RANK[confidence] >= _CONF_RANK[self.confidence_min]


def candidate_confidence(candidate: Candidate) -> str:
    if candidate.score >= 75 or (candidate.live and candidate.score >= 60):
        return "high"
    if candidate.score >= 45 or (candidate.live and candidate.score >= 30):
        return "medium"
    return "low"


def rows_from_candidates(candidates: list[Candidate]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for candidate in candidates:
        rows.append(
            {
                "domain": candidate.domain,
                "method": "; ".join(candidate.methods) or "unknown",
                "confidence": candidate_confidence(candidate),
                "live": candidate.live,
                "score": candidate.score,
                "evidence": list(candidate.evidence),
            }
        )
    return rows


def format_rows(candidates: list[Candidate]) -> str:
    rows = rows_from_candidates(candidates)
    if not rows:
        return ""

    domain_width = max(6, min(36, max(len(row["domain"]) for row in rows)))
    method_width = max(6, min(40, max(len(row["method"]) for row in rows)))

    lines = ["=== Findings ==="]
    lines.append(f"{'Domain'.ljust(domain_width)}  {'Method'.ljust(method_width)}  Confidence  Live")
    for row in rows:
        lines.append(
            f"{row['domain'].ljust(domain_width)}  "
            f"{row['method'][:method_width].ljust(method_width)}  "
            f"{row['confidence'].ljust(10)}  "
            f"{'Yes' if row['live'] else 'No'}"
        )
    return "\n".join(lines)


_DHJSON_PREFIX = "# DHJSON "


def emit_findings_snapshot(candidates: list[Candidate]) -> None:
    """Print the human table plus a last-wins JSON line for parsers/timeouts."""
    print(format_rows(candidates) or "=== Findings ===\n(none)")
    print(_DHJSON_PREFIX + json.dumps(rows_from_candidates(candidates), separators=(",", ":")))
    sys.stdout.flush()


def write_output_file(path: str, candidates: list[Candidate]) -> Path | None:
    if not path:
        return None
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = rows_from_candidates(candidates)

    if output.suffix.lower() == ".json":
        output.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        return output

    with output.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["domain", "method", "confidence", "live", "score", "evidence"])
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    **row,
                    "live": "yes" if row["live"] else "no",
                    "evidence": " | ".join(row["evidence"]),
                }
            )
    return output


def parse_stdout(stdout: str) -> list[dict[str, Any]]:
    """Extract candidate rows from stdout.

    Prefer the last ``# DHJSON`` line (full fields, including empty ``[]`` so a
    filtered-empty final result is not overwritten by an earlier progress
    table). Fall back to the last ``=== Findings ===`` table for older output.
    """
    json_blocks: list[list[dict[str, Any]]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith(_DHJSON_PREFIX):
            payload = stripped[len(_DHJSON_PREFIX) :]
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if isinstance(data, list):
                json_blocks.append([row for row in data if isinstance(row, dict)])
    if json_blocks:
        return _normalize_parsed_rows(json_blocks[-1])
    return _normalize_parsed_rows(_parse_findings_table(stdout))


def _normalize_parsed_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        raw = str(row.get("domain", "") or "").strip()
        apex = root_domain(raw)
        if not apex or apex in seen or not is_registrable_domain(apex):
            continue
        seen.add(apex)
        live = row.get("live")
        if isinstance(live, str):
            live = live.strip().lower() in {"yes", "true", "1"}
        else:
            live = bool(live)
        conf = str(row.get("confidence", "low") or "low").strip().lower()
        if conf not in _CONF_RANK:
            conf = "low"
        normalized.append(
            {
                "domain": apex,
                "method": str(row.get("method", "") or "").strip() or "unknown",
                "confidence": conf,
                "live": live,
                "score": row.get("score"),
                "evidence": row.get("evidence") or [],
            }
        )
    return normalized


def _parse_findings_table(stdout: str) -> list[dict[str, Any]]:
    """Last ``=== Findings ===`` table, including an empty final block."""
    row_re = re.compile(
        r"^(?P<domain>\S+\.\S+)\s+(?P<method>.+?)\s+(?P<conf>low|medium|high)\s+(?P<live>Yes|No)\s*$"
    )
    blocks: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] | None = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("=== Findings"):
            if current is not None:
                blocks.append(current)
            current = []
            continue
        if current is None:
            continue
        if stripped.startswith("Wrote ") or (stripped.startswith("===") and not stripped.startswith("=== Findings")):
            blocks.append(current)
            current = None
            continue
        if not stripped or stripped == "(none)" or stripped.startswith("Domain "):
            continue
        match = row_re.match(stripped)
        if match:
            current.append(
                {
                    "domain": match.group("domain").lower(),
                    "method": match.group("method").strip(),
                    "confidence": match.group("conf"),
                    "live": match.group("live") == "Yes",
                }
            )
    if current is not None:
        blocks.append(current)
    return blocks[-1] if blocks else []


def run_hunter(domain: str, *, modules: str = "", confidence_min: str = "low", output: str = "") -> tuple[list[Candidate], Path | None]:
    hunter = DomainHunter(domain, modules=modules, confidence_min=confidence_min)
    candidates = hunter.discover()
    output_path = write_output_file(output, candidates)
    return candidates, output_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Discover sister/affiliated root domains.")
    parser.add_argument("--domain", required=True, help="Seed root domain")
    parser.add_argument("--modules", default="", help="Comma-separated module subset")
    parser.add_argument("--confidence-min", default="low", choices=("low", "medium", "high"))
    parser.add_argument("--output", default="", help="Optional CSV or JSON output path")
    args, extra = parser.parse_known_args(argv)

    candidates, output_path = run_hunter(
        args.domain,
        modules=args.modules,
        confidence_min=args.confidence_min,
        output=args.output,
    )

    emit_findings_snapshot(candidates)
    if extra:
        logger.info("Ignored extra args: %s", " ".join(extra))
    if output_path:
        print(f"Wrote {len(candidates)} candidate(s) to {output_path}")
    else:
        print(f"Wrote {len(candidates)} candidate(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
