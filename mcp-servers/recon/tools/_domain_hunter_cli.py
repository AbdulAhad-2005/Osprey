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
    tokens = list(_seed_base_tokens(seed_root))
    for token in _safe_tokens(title_text):
        if token not in tokens:
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


def _is_tld_like_label(label: str) -> bool:
    """True when *label* is the first label of any multi-label public suffix.

    Seed labels that are themselves TLD words (``gov`` -> ``gov.uk``,
    ``co`` -> ``co.jp``, ``com`` -> ``com.cn``) generate generic squat
    variants (gov.com, govonline.uk) that are never the seed's sisters.
    Derived from the same PSL snapshot, never hand-maintained.
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


def _crtsh_query(session: Any, query: str, timeout: int = 8) -> list[dict[str, Any]]:
    """crt.sh is flaky (502s/empty bodies are common) — retry with backoff.

    Uses a FRESH request (not ``session``) so the session's urllib3 Retry
    adapter (which already retries 5xx with backoff) cannot multiply with the
    manual loop below and turn one query into 90s.
    """
    import requests

    url = f"https://crt.sh/?q={quote_plus(query)}&output=json"
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            response = requests.get(url, timeout=timeout)
            if not response.ok or not response.text.strip():
                last_error = ValueError(f"crt.sh status {response.status_code}")
                continue
            text = response.text.strip()
            if text.startswith("["):
                data = response.json()
                return data if isinstance(data, list) else []
            last_error = ValueError("crt.sh non-JSON body")
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        if attempt == 0:
            time.sleep(1.5)
    logger.info("crt.sh query failed (%s): %s", query, last_error)
    return []


def _certspotter_query(domain: str, timeout: int = 8) -> list[str]:
    """CT fallback for the direct seed-domain query when crt.sh is unavailable.

    crt.sh is the single passive source three of the six modules lean on, and it
    is documented-flaky (502s / empty bodies). certspotter's free issuances API
    is an independent Certificate Transparency aggregator, so a crt.sh outage no
    longer blinds cert discovery entirely. It returns full issuances (dns_names)
    for a domain+subdomains but has NO substring/token search — so it can only
    back the high-value direct-domain query, not the brand-token searches.
    """
    import requests

    url = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={quote_plus(domain)}&include_subdomains=true&expand=dns_names"
    )
    names: list[str] = []
    try:
        response = requests.get(url, timeout=timeout)
        if not response.ok:
            return []
        data = response.json()
        if isinstance(data, list):
            for issuance in data:
                for name in (issuance.get("dns_names") or []):
                    cleaned = str(name).strip().lower()
                    if cleaned and cleaned not in names:
                        names.append(cleaned)
    except Exception as exc:  # noqa: BLE001
        logger.info("certspotter query failed (%s): %s", domain, exc)
    return names


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
    forms: list[str] = [seed_root]
    if len(label) >= 3 and not _is_tld_like_label(label):
        forms.append(label)
        collapsed = "".join(ch for ch in label if ch.isalnum())
        if collapsed and collapsed != label:
            forms.append(collapsed)
    for token in _seed_base_tokens(seed_root):
        if len(token) < 3:
            continue
        if _is_tld_like_label(token):
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


class DomainHunter:
    """Best-effort sister-domain discovery with multiple weak signals."""

    def __init__(self, domain: str, *, modules: str = "", confidence_min: str = "low") -> None:
        self.seed = normalize_seed_domain(domain)
        self.seed_root = root_domain(self.seed)
        self.seed_tld = self.seed_root.rsplit(".", 1)[-1] if self.seed_root else ""
        self.modules = self._normalize_modules(modules)
        self.confidence_min = confidence_min if confidence_min in _CONF_RANK else "low"
        self.session = _http_session()
        self.candidates: dict[str, Candidate] = {}
        self._brand_tokens: list[str] = _brand_tokens(self.seed_root)
        # Circuit breaker for crt.sh: it is flaky (502s/empty bodies), and a
        # single run may fire up to ~11 crt.sh queries (certs + knowledge_recon
        # tokens + RDAP org tokens). When the service is down, retrying every
        # query serially can burn minutes — so the breaker trips after TWO
        # consecutive empty/failed queries (each already includes retries with
        # backoff) and the rest of the run skips crt.sh work. A single empty
        # result no longer trips it (a token search legitimately returning zero
        # rows is not evidence the service is down), and any successful query
        # resets the counter. The direct-domain query additionally falls back to
        # certspotter (see _collect_cert_signals), so a crt.sh outage does not
        # blind cert discovery entirely.
        self._crtsh_degraded = False
        self._crtsh_failures = 0

    def _query_crtsh(self, query: str) -> list[dict[str, Any]]:
        """Single crt.sh access point honoring the circuit breaker."""
        if self._crtsh_degraded:
            return []
        rows = _crtsh_query(self.session, query)
        if rows:
            self._crtsh_failures = 0
        else:
            self._crtsh_failures += 1
            if self._crtsh_failures >= 2:
                self._crtsh_degraded = True
        return rows

    @staticmethod
    def _normalize_modules(modules: str) -> set[str]:
        if not modules.strip():
            return {"certs", "dns", "asn", "whois", "site_scrape", "knowledge_recon"}
        normalized = {part.strip().lower() for part in modules.split(",") if part.strip()}
        aliases = {
            "crawl": "site_scrape",
            "scrape": "site_scrape",
            "search": "knowledge_recon",
            "rdap": "whois",
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
        # matched by row_re/the "===" checks) marks it as in-progress.
        print(f"# domain_hunter progress: completed={stage!r} candidates_so_far={len(self.candidates)}")
        block = format_rows(list(self.candidates.values()))
        if block:
            print(block)
        sys.stdout.flush()

    def discover(self) -> list[Candidate]:
        if not self.seed_root:
            return []

        if "site_scrape" in self.modules:
            self._collect_site_signals()
            self._emit_progress("site_scrape")
        if "certs" in self.modules:
            self._collect_cert_signals(self.seed_root)
            self._emit_progress("certs")
        if "knowledge_recon" in self.modules:
            self._collect_knowledge_signals()
            self._emit_progress("knowledge_recon")
        if "dns" in self.modules:
            self._collect_dns_signals()
            self._emit_progress("dns")
        if "asn" in self.modules:
            self._collect_reverse_ip_signals()
            self._emit_progress("asn")
        if "whois" in self.modules:
            self._collect_rdap_signals()
            self._emit_progress("whois")

        self._resolve_live_status()
        filtered = [c for c in self.candidates.values() if self._passes_confidence_floor(c)]
        filtered.sort(key=lambda item: (-item.score, not item.live, item.domain))
        return filtered

    def _add_candidate(self, domain: str, *, method: str, points: int, evidence: str) -> None:
        domain = normalize_seed_domain(domain)
        if not domain or "." not in domain:
            return
        if not _is_likely_domain_or_none(domain):
            return
        if is_same_root(domain, self.seed_root):
            return
        # Candidates living at a shared cloud-platform apex (azurewebsites.net,
        # cloudfront.net, github.io, ...) are never an affiliated root — the
        # PSL private section says so authoritatively (see _at_psl_private_apex).
        if _at_psl_private_apex(domain):
            return
        # Tracker/social/platform apexes only get suppressed as weak third-party
        # evidence: SITE-SCRAPE (links/robots/sitemap — a homepage linking to
        # facebook.com or cdnjs.com means nothing) and DNS host records (an NS
        # or MX host at a provider apex like cloudflare.com means the seed USES
        # that provider — the provider apex is never the sister's own name).
        # Certs/ASN evidence still counts, so a platform apex with real
        # signals is not masked.
        if method in ("site_scrape", "dns") and root_domain(domain) in _SITE_LINK_NOISE_ROOTS:
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

    def _collect_cert_signals(self, query: str, *, token_search: bool = False) -> None:
        query = query.strip().lower()
        if not query:
            return
        crt_query = f"%25{query}%25" if token_search and query != self.seed_root else f"%25{self.seed_root}"
        rows = self._query_crtsh(crt_query)
        if not rows and not token_search:
            # crt.sh gave nothing for the high-value direct query — diversify to
            # a second CT aggregator so an outage there doesn't zero out cert
            # discovery. (Token searches can't fall back: certspotter has no
            # substring search.)
            for raw_name in _certspotter_query(self.seed_root):
                candidate = normalize_seed_domain(raw_name)
                if candidate.startswith("*."):
                    candidate = candidate[2:]
                if not candidate:
                    continue
                rd = root_domain(candidate)
                if rd and rd != self.seed_root:
                    self._add_candidate(
                        rd,
                        method="certs",
                        points=_POINTS_CERTS_DIRECT,
                        evidence=f"certspotter: {candidate}",
                    )
            return
        for row in rows:
            names = str(row.get("name_value", "") or "").splitlines()
            common_name = str(row.get("common_name", "") or "").strip()
            entry_evidence = common_name or query
            for raw_name in names:
                candidate = normalize_seed_domain(raw_name.strip().lower())
                if candidate.startswith("*."):
                    candidate = candidate[2:]
                if not candidate:
                    continue
                rd = root_domain(candidate)
                if rd and rd != self.seed_root:
                    points = _POINTS_CERTS_DIRECT if not token_search else _POINTS_CERTS_TOKEN
                    self._add_candidate(
                        rd,
                        method="certs",
                        points=points,
                        evidence=f"crt.sh {entry_evidence}: {candidate}",
                    )

    def _collect_knowledge_signals(self) -> None:
        """Brand-token crt.sh searches + Wikidata official websites + TLD variants.

        ``knowledge_recon`` is the "brand relationship" module: it searches the
        brand tokens on certificate transparency, pulls the brand entity's
        official website from Wikidata (P856), and guesses TLD/pattern variants
        (geo.tv -> geonews.tv, geotv.pk) — each verified by DNS before scoring.
        """
        for token in self._brand_tokens[:3]:
            self._collect_cert_signals(token, token_search=True)

        # Wikidata anchors on the SEED ROOT first: a bare brand token can bind
        # to a namesake entity (abc.xyz -> the Disney "ABC"), which manufactured
        # false "official website" candidates. Only when the seed itself has no
        # entity do we fall back — to progressively looser seed-derived forms
        # (label -> collapsed label -> seed tokens), never to a brand token
        # that is not part of the seed's own name.
        wikidata_websites: list[str] = []
        for form in _wikidata_search_forms(self.seed_root):
            hit_entity, websites = _wikidata_official_websites(self.session, form)
            if hit_entity:
                wikidata_websites = websites
                break
        for website in wikidata_websites:
            host = urlparse(website if "://" in website else f"//{website}").hostname
            if not host:
                continue
            rd = root_domain(host)
            if rd and rd != self.seed_root:
                self._add_candidate(
                    rd,
                    method="wikidata",
                    points=_POINTS_WIKIDATA,
                    evidence=f"wikidata P856: {website}",
                )

        if self.seed_tld:
            # Variant guessing, generic (no hardcoded English word list):
            #   * BARE brand token across the seed TLD + generic gTLDs
            #     (geo.tv -> geo.com/geo.net/geo.io ...) — language-independent.
            #   * COMPOUND token + brandword (geo + "news" -> geonews.tv) where
            #     the brandword is derived from the seed's OWN discovered brand
            #     tokens (homepage title, populated by site_scrape which runs
            #     first), NOT a fixed list — so it adapts per-domain/language.
            # Every probe is DNS-verified before scoring, so the broader fan-out
            # cannot inflate results with dead guesses.
            base_tokens = [
                token
                for token in _seed_base_tokens(self.seed_root)
                if len(token) >= 3 and not _is_tld_like_label(token)
            ]
            derived_suffixes = [
                token
                for token in self._brand_tokens
                if token not in base_tokens and 3 <= len(token) <= 8 and token.isalnum()
            ][:4]
            tld_set = tuple(dict.fromkeys((self.seed_tld,) + _VARIANT_GTLDS))
            seen_variants: set[str] = set()
            for token in base_tokens:
                variants = [(token, tld_set)] + [
                    # Compound variants stay on the seed TLD to bound noise.
                    (f"{token}{suffix}", (self.seed_tld,))
                    for suffix in derived_suffixes
                ]
                for variant, probe_tlds in variants:
                    if variant in seen_variants:
                        continue
                    seen_variants.add(variant)
                    for tld in probe_tlds:
                        probe = f"{variant}.{tld}"
                        if _is_likely_domain_or_none(probe) and _domain_resolves(probe):
                            self._add_candidate(
                                probe,
                                method="tld_variant",
                                points=_POINTS_TLD_VARIANT,
                                evidence=f"pattern variant {probe} resolves",
                            )

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

        for token in org_tokens[:8]:
            self._collect_cert_signals(token, token_search=True)

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

    DomainHunter prints a "=== Findings ===" block after EVERY module (see
    DomainHunter._emit_progress), not just once at the end — so a timed-out,
    killed-mid-run process still has a usable partial block on stdout. Collect
    ALL such blocks and return the LAST one: on a normal completed run that's
    the final full result (unchanged behavior from before); on a timeout kill
    it's the latest progress snapshot instead of nothing.
    """
    row_re = re.compile(r"^(?P<domain>\S+\.\S+)\s+(?P<method>.+?)\s+(?P<conf>low|medium|high)\s+(?P<live>Yes|No)\s*$")
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
        if stripped.startswith("Wrote ") or stripped.startswith("==="):
            blocks.append(current)
            current = None
            continue
        if not stripped or stripped == "(none)":
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

    print(format_rows(candidates) or "=== Findings ===\n(none)")
    if extra:
        logger.info("Ignored extra args: %s", " ".join(extra))
    if output_path:
        print(f"Wrote {len(candidates)} candidate(s) to {output_path}")
    else:
        print(f"Wrote {len(candidates)} candidate(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
