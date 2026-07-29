"""Shared implementation for sister-domain discovery.

The tool is intentionally modular so it can be used both from the standalone
CLI entrypoint inside ``mcp-servers/recon/tools/domain-hunter/`` and from the
recon MCP wrapper module.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urlparse

logger = logging.getLogger(__name__)

_COMMON_MULTI_SUFFIXES = {
    "ac.uk",
    "co.uk",
    "gov.uk",
    "ltd.uk",
    "me.uk",
    "net.uk",
    "org.uk",
    "sch.uk",
    "com.au",
    "edu.au",
    "gov.au",
    "net.au",
    "org.au",
    "com.br",
    "com.cn",
    "com.hk",
    "com.mx",
    "com.tr",
    "com.pk",
    "edu.pk",
    "gov.pk",
    "net.pk",
    "org.pk",
    "ac.pk",
    "edu.in",
    "gov.in",
    "net.in",
    "org.in",
    "co.in",
    "nic.in",
}

# Shared CDN/cloud/hosting infrastructure — a target proxied through one of
# these (Cloudflare, Akamai, etc.) shares its edge IP with millions of
# unrelated domains. Reverse-IP/ASN co-location on these roots is not an
# organizational-affiliation signal, so candidates rooted here are rejected
# outright regardless of score (a shared CDN edge trivially resolves + is
# "live", which otherwise crosses the medium-confidence threshold on ASN
# points alone).
_KNOWN_SHARED_INFRA_ROOTS = frozenset(
    {
        "cloudflare.com",
        "cloudflare.net",
        "cloudflareinsights.com",
        "cloudflarestream.com",
        "akamai.com",
        "akamaized.net",
        "akamaitechnologies.com",
        "akamaiedge.net",
        "fastly.com",
        "fastlylb.net",
        "fastly.net",
        "amazonaws.com",
        "cloudfront.net",
        "googleusercontent.com",
        "google.com",
        "googleapis.com",
        "azureedge.net",
        "azurewebsites.net",
        "azure.com",
        "incapsula.com",
        "imperva.com",
        "sucuri.net",
        "stackpathcdn.com",
        "edgekey.net",
        "edgesuite.net",
    }
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_DOMAIN_RE = re.compile(r"(?:https?://)?(?:www\.)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)

_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


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
    """Best-effort registrable domain extraction.

    Prefers ``tldextract`` when available, but falls back to a compact built-in
    heuristic so the tool still works in minimal environments.
    """
    host = normalize_seed_domain(host)
    if not host or host.count(".") < 1:
        return host

    try:
        import tldextract  # type: ignore

        extracted = tldextract.extract(host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
    except Exception:
        pass

    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return host

    suffix2 = ".".join(labels[-2:])
    suffix3 = ".".join(labels[-3:])
    if suffix2 in _COMMON_MULTI_SUFFIXES and len(labels) >= 3:
        return suffix3
    if labels[-2] in {"edu", "gov", "ac", "co", "com", "org", "net"} and len(labels[-1]) <= 3:
        return suffix3
    return suffix2


def is_same_root(left: str, right: str) -> bool:
    return root_domain(left) == root_domain(right)


def _safe_tokens(text: str) -> list[str]:
    tokens = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9-]{2,}", text):
        cleaned = token.lower().strip("-.")
        if cleaned and cleaned not in tokens:
            tokens.append(cleaned)
    return tokens


_FILE_LIKE_TLDS: frozenset[str] = frozenset({
    "css", "js", "json", "xml", "html", "htm", "svg", "png", "jpg",
    "jpeg", "gif", "webp", "ico", "woff", "woff2", "ttf", "eot",
    "mp4", "mp3", "pdf", "zip", "tar", "gz", "exe", "dmg", "apk",
    "txt", "md", "yaml", "yml", "ts", "tsx", "jsx", "map",
    "webmanifest",
    "aspx", "asp", "mspx", "ashx", "asmx",
    "php", "php3", "php4", "php5", "phtml",
    "jsp", "jspx",
    "cfm", "cfc",
    "shtml", "dhtml",
    "cgi", "pl", "py",
    "do", "action", "rst",
})

# Real gTLDs longer than 6 characters that are actually delegated in the DNS
# root zone.  Anything not in this set with a "TLD" > 6 chars is almost
# certainly a code-identifier false positive.
_KNOWN_LONG_TLDS: frozenset[str] = frozenset({
    "abogado", "academy", "accountants", "active", "actor",
    "adult", "agency", "airforce", "apartments", "archi",
    "associates", "attorney", "auction", "audio",
    "band", "bank", "bargains", "berlin", "bike", "bingo",
    "bio", "black", "blog", "blue", "boutique", "broker",
    "build", "builders", "business", "buy",
    "cab", "cafe", "cam", "camera", "camp", "capital",
    "cards", "care", "career", "careers", "cars", "casa",
    "cash", "casino", "catering", "center", "ceo",
    "channel", "chat", "church", "city", "claims",
    "cleaning", "clinic", "clothing", "cloud", "club",
    "coach", "codes", "coffee", "college", "community",
    "company", "compare", "computer", "condos", "consulting",
    "contact", "contractors", "cooking", "cool", "country",
    "coupon", "coupons", "courses", "cricket", "cruises",
    "dad", "dance", "date", "dating", "day", "deals",
    "degree", "delivery", "delta", "democrat", "dental",
    "dentist", "design", "diamonds", "diet", "digital",
    "direct", "directory", "discount", "doctor", "dog",
    "domains", "dot", "download", "durban",
    "earth", "education", "email", "energy", "engineer",
    "engineering", "enterprises", "equipment", "esq",
    "estate", "events", "exchange", "expert", "exposed",
    "express",
    "fail", "faith", "family", "fan", "fans", "farm",
    "fashion", "feedback", "film", "finance", "financial",
    "fish", "fishing", "fitness", "flights", "florist",
    "flowers", "fly", "foo", "food", "football", "forex",
    "forsale", "forum", "foundation", "fun", "fund",
    "furniture", "futbol", "fyi",
    "gallery", "game", "games", "garden", "gent", "gift",
    "gifts", "gives", "glass", "global", "gmbh", "gold",
    "golf", "graphics", "gratis", "green", "gripe",
    "group", "guide", "guitars", "guru",
    "haus", "health", "healthcare", "help", "here",
    "hiphop", "hiv", "hockey", "holdings", "holiday",
    "homes", "horse", "hospital", "host", "hosting",
    "hotel", "house",
    "immo", "immobilien", "industries", "info", "ing",
    "ink", "institute", "insurance", "international",
    "investments", "irish", "islam",
    "jewelry", "jobb", "jobs", "journal", "juegos",
    "kaufen", "kitchen", "kiwi", "koeln",
    "land", "law", "lawyer", "lease", "legal", "lgbt",
    "life", "lighting", "limited", "limo", "link",
    "live", "llc", "loan", "loans", "lol", "lotto",
    "love", "ltd",
    "maison", "management", "market", "marketing",
    "markets", "mba", "media", "memorial", "men",
    "menu", "miami", "mobi", "moda", "monster", "mortgage",
    "movie", "music",
    "nagoya", "name", "navy", "network", "news", "next",
    "ninja", "nokia",
    "observer", "okinawa", "one", "online", "organic",
    "org", "oversees",
    "page", "partners", "parts", "party", "pet", "photo",
    "photography", "photos", "physio", "pics", "pictures",
    "pid", "pink", "pizza", "place", "plumbing", "plus",
    "poker", "porn", "press", "prime", "pro", "productions",
    "prof", "promo", "properties", "property", "protection",
    "pub",
    "qpon", "queens",
    "racing", "radio", "realty", "recipes", "red",
    "rehab", "reise", "reisen", "rent", "rentals", "repair",
    "report", "republican", "rest", "restaurant", "review",
    "reviews", "rich", "rip", "rocks", "rodeo", "room",
    "rugby", "run",
    "sale", "salon", "sarl", "school", "schule", "science",
    "scot", "search", "security", "services", "sex", "sexy",
    "shiksha", "shoes", "shop", "shopping", "show", "shows",
    "sites", "soccer", "social", "software", "solar",
    "solutions", "sony", "space", "sport", "spots",
    "star", "stockholm", "storage", "store", "stream",
    "studio", "study", "style", "sucks", "supplies",
    "supply", "support", "surgery", "systems",
    "taipei", "talk", "tattoo", "tax", "taxi", "team",
    "tech", "technology", "tennis", "theater", "theatre",
    "tickets", "tienda", "tips", "tires", "today", "tokyo",
    "tools", "top", "tours", "town", "toys", "trade",
    "trading", "training", "travel", "trust",
    "university", "uno", "vacations", "ventures", "vet",
    "viajes", "video", "villas", "vin", "vip", "vision",
    "vodka", "vote", "voting", "voto", "voyage",
    "wang", "watch", "webcam", "website", "wedding",
    "wiki", "win", "wine", "work", "works", "world", "wtf",
    "xxx", "xyz",
    "yachts", "yokohama", "yoga", "youtube",
    "zone",
})


def _tldextract_uses_fallback() -> bool:
    """Detect if tldextract falls back to last-label-as-suffix (v3.x behaviour)
    or returns empty for unrecognised suffixes (v5.x+)."""
    try:
        import tldextract as _te  # type: ignore
        test = _te.extract("validate.thisisnotarealsuffix99")
        return bool(test.suffix)
    except Exception:
        return False


_TLD_FALLBACK = _tldextract_uses_fallback()


def _is_likely_domain_or_none(host: str) -> str | None:
    """Return *host* if it looks like a real registered domain, else ``None``."""
    host = host.strip().lower()
    if not host or "." not in host:
        return None
    labels = host.rsplit(".", 1)
    if len(labels) != 2:
        return None
    domain_label, tld = labels
    if len(domain_label) < 2:
        return None
    if len(tld) < 2 or len(tld) > 24:
        return None
    if tld in _FILE_LIKE_TLDS:
        return None
    try:
        import tldextract as _te  # type: ignore
        ext = _te.extract(host)
        if ext.suffix and ext.domain:
            if _TLD_FALLBACK:
                # tldextract falls back to last-label-as-suffix.
                # Accept only short (≤6) TLDs or explicitly known long ones.
                if len(tld) <= 6 or tld in _KNOWN_LONG_TLDS:
                    return host
                return None
            # v5.x+: tldextract returned suffix → it's in the PSL
            return host
        # tldextract rejected the suffix
        return None
    except Exception:
        pass
    # No tldextract: accept common-length TLDs only
    if len(tld) <= 6 or tld in _KNOWN_LONG_TLDS:
        return host
    return None


def _brand_tokens(seed_root: str, title_text: str = "") -> list[str]:
    tokens = []
    base = seed_root.split(".")[0]
    for token in _safe_tokens(base):
        if token not in tokens:
            tokens.append(token)
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


def _http_session() -> "requests.Session":
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
            )
        }
    )
    # Aggressive retry + short connect/read timeouts to avoid hanging on dead hosts
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _fetch(session: Any, url: str, timeout: int = 8) -> tuple[str, str]:
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
        if response.ok or response.status_code in {401, 403}:
            return response.text, response.url
    except Exception:
        return "", url
    return "", url


def _live_probe(session: Any, domain: str, timeout: int = 5) -> tuple[bool, str | None]:
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
        results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        for item in results:
            ip = item[4][0]
            if ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    return ips


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


def _crtsh_query(session: Any, query: str, timeout: int = 10) -> list[dict[str, Any]]:
    url = f"https://crt.sh/?q={quote_plus(query)}&output=json"
    try:
        response = session.get(url, timeout=timeout)
        if not response.ok or not response.text.strip():
            return []
        text = response.text.strip()
        if text.startswith("["):
            data = json.loads(text)
            return data if isinstance(data, list) else []
        return []
    except Exception:
        return []


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
                return domains
        except Exception:
            continue
    return domains


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
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)
        self.score += points


class DomainHunter:
    """Best-effort sister-domain discovery with multiple weak signals."""

    def __init__(self, domain: str, *, modules: str = "", confidence_min: str = "low") -> None:
        self.seed = normalize_seed_domain(domain)
        self.seed_root = root_domain(self.seed)
        self.modules = self._normalize_modules(modules)
        self.confidence_min = confidence_min if confidence_min in _CONF_RANK else "low"
        self.session = _http_session()
        self.candidates: dict[str, Candidate] = {}
        self._brand_tokens: list[str] = [token for token in _brand_tokens(self.seed_root) if token != self.seed_root]

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
            for token in self._brand_tokens[:3]:
                self._collect_cert_signals(token, token_search=True)
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
        if root_domain(domain) in _KNOWN_SHARED_INFRA_ROOTS:
            return
        candidate = self.candidates.get(domain)
        if candidate is None:
            candidate = Candidate(domain=domain)
            self.candidates[domain] = candidate
        candidate.add(method, points, evidence)

    def _collect_site_signals(self) -> None:
        homepage, final_url = _fetch(self.session, f"https://{self.seed_root}")
        if not homepage:
            homepage, final_url = _fetch(self.session, f"http://{self.seed_root}")
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
                            points=38,
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
            for node_text in (title,):
                if token in node_text.lower() and len(token_pool) > 1:
                    self._brand_tokens.append(token)
                    break

        if final_url and final_url != f"https://{self.seed_root}":
            final_host = root_domain(urlparse(final_url).hostname or "")
            if final_host and final_host != self.seed_root:
                self._add_candidate(
                    final_host,
                    method="site_scrape",
                    points=18,
                    evidence=f"redirected to {final_url}",
                )

        robots, _ = _fetch(self.session, f"https://{self.seed_root}/robots.txt")
        sitemap, _ = _fetch(self.session, f"https://{self.seed_root}/sitemap.xml")
        for blob, label in ((robots, "robots.txt"), (sitemap, "sitemap.xml")):
            if not blob:
                continue
            for domain in _extract_domains(blob):
                rd = root_domain(domain)
                if rd and rd != self.seed_root:
                    self._add_candidate(
                        rd,
                        method="site_scrape",
                        points=24,
                        evidence=f"{label} reference: {domain}",
                    )

    def _collect_cert_signals(self, query: str, *, token_search: bool = False) -> None:
        query = query.strip().lower()
        if not query:
            return
        crt_query = f"%25{query}%25" if token_search and query != self.seed_root else f"%25{self.seed_root}"
        rows = _crtsh_query(self.session, crt_query)
        for row in rows:
            names = str(row.get("name_value", "") or "").splitlines()
            common_name = str(row.get("common_name", "") or "").strip()
            entry_evidence = common_name or query
            for raw_name in names:
                candidate = normalize_seed_domain(raw_name.strip().lstrip("*.").lower())
                if not candidate:
                    continue
                rd = root_domain(candidate)
                if rd and rd != self.seed_root:
                    points = 40 if not token_search else 28
                    self._add_candidate(
                        rd,
                        method="certs",
                        points=points,
                        evidence=f"crt.sh {entry_evidence}: {candidate}",
                    )

    def _collect_dns_signals(self) -> None:
        hosts = _resolve_dns_hosts(self.seed_root)
        for host in hosts:
            rd = root_domain(host)
            if rd and rd != self.seed_root:
                self._add_candidate(
                    rd,
                    method="dns",
                    points=20,
                    evidence=f"shared DNS host: {host}",
                )

    def _collect_reverse_ip_signals(self) -> None:
        ips = _resolve_ips(self.seed_root)
        for ip in ips[:4]:
            domains = _reverse_ip_lookup(self.session, ip)
            for domain in domains:
                rd = root_domain(domain)
                if rd and rd != self.seed_root:
                    self._add_candidate(
                        rd,
                        method="asn",
                        points=34,
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
        for candidate in self.candidates.values():
            live, url = _live_probe(self.session, candidate.domain)
            candidate.live = live
            if live and url:
                candidate.add("live_probe", 12, f"live at {url}")

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

    DomainHunter now prints a "=== Findings ===" block after EVERY module (see
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
        if not stripped or stripped.startswith("Domain ") or stripped.startswith("Domain") or stripped == "(none)":
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
