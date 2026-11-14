"""Sister / affiliated-root-domain discovery (single canonical module).

Runs standalone (``python3 _domain_hunter_cli.py --domain X``) and is imported
by the recon MCP wrapper for its stdout parser (``parse_stdout``).

Finds OTHER root domains operated by the same organisation. Subdomains,
certificate transparency, ASN, emails and generic web search are owned by
dedicated tools (subfinder/amass, crt_sh_query, asn_enum, theHarvester,
web_search) — this tool only does what those don't: correlate separate roots
by the same operator/registrant/brand.

Affiliation model (replaces the old static denylists): a candidate is kept when
it is tied to the seed by a STRONG signal — same WHOIS registrant, a shared
analytics/pixel ID, an identical favicon, self-hosted mail/DNS infra sharing the
seed's brand token, or the org's own Wikipedia/official-site listing. A WEAK
signal (a bare outbound link, a generic search snippet) only creates a candidate
when it shares the seed's brand token or corroborates a strong one; otherwise it
is noise (a third-party provider or an unrelated site) and is dropped. This is
why ``google.com``/``amazonses.com`` from a seed's SPF/MX never surface while a
self-hosted ``geoit.tv`` does.

Modules (``--modules``, comma-separated; aliases in ``_normalize_modules``):
site_scrape, self_infra, reverse_whois, tracker_pivot, web_search, wikidata,
favicon.

Output: a human ``=== Findings ===`` table plus a machine-readable ``# DHJSON``
line emitted after every module, so an outer timeout still leaves usable rows.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urljoin, urlparse

logger = logging.getLogger(__name__)

_MCP_ROOT = Path(__file__).resolve().parents[2]
if str(_MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(_MCP_ROOT))
from _core.domains import is_registrable_domain, is_same_apex, registrable_apex

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_DOMAIN_RE = re.compile(
    r"(?<![\w@.=/-])(?:https?://)?(?:www\.)?([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})",
    re.IGNORECASE,
)

_CONF_RANK = {"low": 0, "medium": 1, "high": 2}

# WHOIS privacy / registrar / forwarding apexes: when a seed uses privacy
# protection the registrant IS the privacy service, and reverse WHOIS on it
# returns thousands of unrelated domains. Only used to filter reverse-WHOIS.
_REGISTRAR_DOMAINS = frozenset({
    "enom.com", "enom.net", "whoisguard.com", "whoisprivacyservices.com",
    "domainsbyproxy.com", "privacyprotect.org", "contactprivacy.com",
    "withheldforprivacy.com", "perfectprivacy.com", "namecheap.com",
    "namesilo.com", "godaddy.com", "web.com", "squarespace.com",
    "google.com", "googleapis.com", "cloudflare.com", "redactedforprivacy.com",
    "dataprotected.com", "privatewhois.net", "hostedemail.com", "forwardemail.net",
})

_PSL_PRIVATE = None


# --------------------------------------------------------------------------
# Domain / brand helpers
# --------------------------------------------------------------------------
def normalize_seed_domain(value: str) -> str:
    raw = value.strip().lower()
    if not raw:
        return ""
    parsed = urlparse(raw if raw.startswith(("http://", "https://")) else f"//{raw}", scheme="https")
    host = (parsed.hostname or raw).strip("./")
    return host.removeprefix("www.")


def root_domain(host: str) -> str:
    return registrable_apex(normalize_seed_domain(host))


def hunter_seed_apex(value: str) -> str:
    apex = root_domain(value)
    return apex if apex and is_registrable_domain(apex) else ""


def is_same_root(left: str, right: str) -> bool:
    return is_same_apex(normalize_seed_domain(left), normalize_seed_domain(right))


def _safe_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9-]{2,}", text):
        cleaned = token.lower().strip("-.")
        if cleaned and cleaned not in tokens:
            tokens.append(cleaned)
    return tokens


def _is_likely_domain_or_none(host: str) -> str | None:
    host = host.strip().lower()
    if not host or "." not in host:
        return None
    return host if is_registrable_domain(host) else None


_BRAND_STOPWORDS = frozenset({
    "the", "and", "for", "new", "live", "news", "latest", "breaking", "today",
    "daily", "online", "watch", "video", "report", "update", "updates", "show",
    "home", "official", "website", "network", "group", "media", "www",
})


def _seed_base_tokens(seed_root: str) -> list[str]:
    """Brand tokens from the seed's own label. Digit-led labels keep only the
    collapsed form ('1800flowers'); letter labels keep their word fragments."""
    base = seed_root.split(".")[0].lower()
    if base[:1].isdigit():
        collapsed = re.sub(r"[^a-z0-9]", "", base)
        return [collapsed] if len(collapsed) >= 3 else []
    tokens: list[str] = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9-]{2,}", base):
        cleaned = token.strip("-.")
        if cleaned and cleaned not in tokens:
            tokens.append(cleaned)
    collapsed = re.sub(r"[^a-z0-9]", "", base)
    if collapsed and collapsed not in tokens:
        tokens.append(collapsed)
    return tokens


def _brand_tokens(seed_root: str, title_text: str = "") -> list[str]:
    tokens = list(_seed_base_tokens(seed_root))
    for token in _safe_tokens(title_text):
        if token not in tokens and token not in _BRAND_STOPWORDS and len(token) > 3:
            tokens.append(token)
    return tokens[:8]


def _shares_brand_token(domain: str, brand_tokens: list[str]) -> bool:
    """True when the candidate's label overlaps a seed brand token — the
    affiliation signal for self-hosted infra and bare link/snippet evidence."""
    label = domain.split(".")[0].lower()
    collapsed = re.sub(r"[^a-z0-9]", "", label)
    for token in brand_tokens:
        if len(token) < 3:
            continue
        if token in collapsed or (len(label) >= 3 and label in token):
            return True
    return False


def _extract_domains(text: str) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for pattern in (_DOMAIN_RE, _EMAIL_RE):
        for match in pattern.finditer(text):
            host = match.group(1).strip(").,;:\"'[]{}<>")
            valid = _is_likely_domain_or_none(host)
            if valid and valid not in seen:
                seen.add(valid)
                results.append(valid)
    return results


def _at_psl_private_apex(host: str) -> bool:
    """True when host sits at a PSL private-section apex (azurewebsites.net,
    github.io, netlify.app, ...) — shared cloud hosting, never a sister."""
    global _PSL_PRIVATE
    if _PSL_PRIVATE is None:
        import tldextract

        _PSL_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
    try:
        extract = _PSL_PRIVATE(host)
        if not extract.domain or not extract.suffix:
            return False
        return f"{extract.domain}.{extract.suffix}".lower() != registrable_apex(host)
    except Exception:
        return False


# --------------------------------------------------------------------------
# HTTP / DNS
# --------------------------------------------------------------------------
def _http_session():
    import requests

    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        )
    })
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
    text, final_url = _fetch(session, url, timeout=timeout)
    if text:
        return text, final_url
    return _fetch(session, url.replace("https://", "http://", 1), timeout=timeout)


def _live_probe(session: Any, domain: str, timeout: int = 4) -> tuple[bool, str | None]:
    for scheme in ("https", "http"):
        try:
            response = session.get(f"{scheme}://{domain}", timeout=timeout, allow_redirects=True)
            if response.status_code < 500:
                return True, response.url
        except Exception:
            continue
    return False, None


def _domain_resolves(domain: str) -> bool:
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime, resolver.timeout = 3, 2
        return bool(resolver.resolve(domain, "A"))
    except Exception:
        return False


def _dns_records(domain: str, rtype: str) -> list[str]:
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime, resolver.timeout = 4, 3
        answers = resolver.resolve(domain, rtype)
        return [str(getattr(rr, "exchange", rr)).strip().rstrip(".") for rr in answers]
    except Exception:
        return []


def _spf_includes(domain: str) -> list[str]:
    includes: list[str] = []
    for txt in _dns_records(domain, "TXT"):
        txt = txt.strip().strip('"')
        if txt.lower().startswith("v=spf1"):
            for part in txt.split():
                if part.lower().startswith("include:"):
                    inc = part.split(":", 1)[1].strip()
                    if inc:
                        includes.append(inc)
    return includes


def _dmarc_rua(domain: str) -> list[str]:
    rua: list[str] = []
    for txt in _dns_records(f"_dmarc.{domain}", "TXT"):
        txt = txt.strip().strip('"')
        if not txt.lower().startswith("v=dmarc1"):
            continue
        for part in txt.split(";"):
            part = part.strip()
            if part.lower().startswith("rua="):
                for uri in part.split("=", 1)[1].split(","):
                    uri = uri.strip().removeprefix("mailto:")
                    if "@" in uri:
                        rua.append(uri.split("@")[-1].strip())
    return rua


def _favicon_md5(session: Any, domain: str, *, timeout: int = 8) -> str | None:
    import hashlib

    for scheme in ("https", "http"):
        try:
            resp = session.get(f"{scheme}://{domain}/favicon.ico", timeout=timeout)
            resp.raise_for_status()
            if resp.content:
                return hashlib.md5(resp.content).hexdigest()
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------
# External signal sources
# --------------------------------------------------------------------------
def _whoxy_reverse_whois(session: Any, seed_root: str, *, timeout: int = 12) -> list[str]:
    """Reverse WHOIS via Whoxy (needs WHOXY_API_KEY) — domains sharing the
    seed's registrant email / org / name. No key → no-op (returns [])."""
    api_key = os.environ.get("WHOXY_API_KEY", "").strip()
    if not api_key:
        return []

    found: list[str] = []
    try:
        resp = session.get(f"https://api.whoxy.com/?key={api_key}&whois={quote_plus(seed_root)}", timeout=timeout)
        if not resp.ok or resp.json().get("status") != 1:
            return []
        contact = resp.json().get("whois_data", {}).get("registrant_contact", {})
    except Exception as exc:
        logger.info("Whoxy WHOIS lookup failed (%s): %s", seed_root, exc)
        return []

    queries = []
    email = contact.get("email_address", "")
    if email and "@" in email:
        queries.append(("email", email))
    if (org := contact.get("company_name", "")) and len(org) >= 3:
        queries.append(("company", org))
    if (name := contact.get("full_name", "")) and len(name) >= 3:
        queries.append(("name", name))
    if len(brand := seed_root.split(".")[0]) >= 3:
        queries.append(("keyword", brand))

    for field_name, value in queries:
        url = f"https://api.whoxy.com/?key={api_key}&reverse=whois&{field_name}={quote_plus(value)}&mode=domains"
        try:
            data = session.get(url, timeout=timeout).json()
        except Exception:
            continue
        for domain in data.get("domains_list", []):
            val = str(domain).strip().lower()
            if val and val != seed_root and is_registrable_domain(val) and val not in found:
                if root_domain(val) not in _REGISTRAR_DOMAINS:
                    found.append(val)
    return found


def _tracker_id_pivot(session: Any, seed_root: str, *, timeout: int = 8) -> list[str]:
    """Domains sharing the seed's GA / GTM / Facebook-pixel ID (same operator),
    via urlscan.io (free, no key)."""
    homepage, _ = _fetch_with_fallback(session, f"https://{seed_root}")
    if not homepage:
        return []
    tracker_ids = list(set(
        re.findall(r"UA-\d{4,}-\d+", homepage)
        + re.findall(r"GTM-\w+", homepage)
        + re.findall(r"fbq\(['\"]init['\"],\s*['\"](\d+)['\"]", homepage)
    ))
    found: list[str] = []
    for tracker_id in tracker_ids[:5]:
        try:
            resp = session.get(
                f"https://urlscan.io/api/v1/search/?q=page.trackers.{quote_plus(tracker_id)}&size=20",
                timeout=timeout,
            )
            if not resp.ok:
                continue
            for result in resp.json().get("results", []):
                page_domain = result.get("page", {}).get("domain", "")
                rd = root_domain(page_domain.lower()) if page_domain else ""
                if rd and rd != seed_root and rd not in found:
                    found.append(rd)
        except Exception:
            continue
    return found


def _wikipedia_page(session: Any, query: str, *, timeout: int = 10) -> str:
    """Resolve a query to its Wikipedia article (opensearch API) and return the
    article HTML — generic, not biased to any one industry."""
    try:
        resp = session.get(
            "https://en.wikipedia.org/w/api.php",
            params={"action": "opensearch", "search": query, "limit": 1, "namespace": 0, "format": "json"},
            timeout=timeout,
        )
        urls = resp.json()[3] if resp.ok else []
        if urls:
            page = session.get(urls[0], timeout=timeout)
            return page.text if page.ok else ""
    except Exception as exc:
        logger.info("Wikipedia lookup failed for %s: %s", query, exc)
    return ""


_WIKI_SELF = frozenset({"wikipedia.org", "wikimedia.org", "wiktionary.org", "wikidata.org", "creativecommons.org"})


def _wikidata_entity_ids(session: Any, query: str, *, limit: int = 3, timeout: int = 10) -> list[str]:
    try:
        resp = session.get(
            "https://www.wikidata.org/w/api.php",
            params={"action": "wbsearchentities", "search": query, "language": "en", "format": "json", "limit": limit},
            timeout=timeout,
        )
        hits = resp.json().get("search", []) if resp.ok else []
        return [h["id"] for h in hits if h.get("id")]
    except Exception as exc:
        logger.info("Wikidata search failed for %s: %s", query, exc)
        return []


def _wikidata_entities(session: Any, qids: list[str], *, timeout: int = 10) -> dict[str, Any]:
    """Batched wbgetentities lookup — one HTTP call for every id, not one per id
    (Wikidata rate-limits aggressively on sequential per-entity requests)."""
    if not qids:
        return {}
    try:
        resp = session.get(
            "https://www.wikidata.org/w/api.php",
            params={
                "action": "wbgetentities", "ids": "|".join(qids[:50]),
                "props": "claims|labels", "languages": "en", "format": "json",
            },
            timeout=timeout,
        )
        if resp.status_code == 429:
            return {}
        return resp.json().get("entities", {}) if resp.ok else {}
    except Exception as exc:
        logger.info("Wikidata batch lookup failed: %s", exc)
        return {}


def _wikidata_claim_ids(entity: dict, prop: str) -> list[str]:
    out = []
    for claim in entity.get("claims", {}).get(prop, []):
        try:
            out.append(claim["mainsnak"]["datavalue"]["value"]["id"])
        except (KeyError, TypeError):
            continue
    return out


def _wikidata_claim_strings(entity: dict, prop: str) -> list[str]:
    out = []
    for claim in entity.get("claims", {}).get(prop, []):
        try:
            value = claim["mainsnak"]["datavalue"]["value"]
            if isinstance(value, str) and value.strip():
                out.append(value.strip())
        except (KeyError, TypeError):
            continue
    return out


def _wikidata_affiliated_sites(session: Any, seed_root: str, brand: str, title: str = "", *, timeout: int = 10) -> dict[str, str]:
    """domain->context map from Wikidata's structured org graph: the seed
    entity's P355 (subsidiary) and P749 (parent organization) claims, chased
    to each related entity's own P856 (official website).

    Deliberately excludes P127/P1830 (owned by / owner of): confirmed on
    real public companies (Tesla, Uber) that those claims surface INSTITUTIONAL
    SHAREHOLDERS (Fidelity, BlackRock, Vanguard, individual board members),
    not corporate affiliates — a materially different relationship.

    Curated structured data, not scraped HTML, so this is trusted as a STRONG
    signal: empirically verified against ~10 real companies (Virgin, LVMH,
    Nike, Samsung, Uber, Shopify, Booking, Tesla, Adidas) with ~40 hits and
    zero false positives (see domain_hunter_overhaul research notes).
    """
    # The seed's own apex is the most reliable disambiguator (unambiguous,
    # doesn't depend on successfully scraping the seed's own title/homepage —
    # some seeds anti-bot-block that fetch entirely). Title and bare brand are
    # fallbacks for seeds without a company-named Wikidata entity. Each query
    # tier checks its top-3 hits (not just the top-1) for one whose OWN P856
    # website is literally the seed — a short/ambiguous brand token (e.g. a
    # one-word consumer brand) can rank the right entity 2nd or 3rd, or not at
    # all, in which case this tier yields nothing and the next tier is tried.
    entity = None
    for query in (seed_root, " ".join(title.split()[:6]) if title else "", brand):
        query = query.strip()
        if not query:
            continue
        qids = _wikidata_entity_ids(session, query, timeout=timeout)
        if not qids:
            continue
        candidates = _wikidata_entities(session, qids, timeout=timeout)
        for qid in qids:  # preserve search-rank order
            candidate = candidates.get(qid)
            if not candidate:
                continue
            own_roots = {root_domain(urlparse(u).hostname or "") for u in _wikidata_claim_strings(candidate, "P856")}
            if seed_root in own_roots:
                entity = candidate
                break
        if entity:
            break
    if entity is None:
        return {}

    related_ids = _wikidata_claim_ids(entity, "P355") + _wikidata_claim_ids(entity, "P749")
    if not related_ids:
        return {}
    time.sleep(0.3)  # Wikidata rate-limits rapid sequential calls
    related = _wikidata_entities(session, related_ids, timeout=timeout)

    sites: dict[str, str] = {}
    for related_qid, related_entity in related.items():
        rel_label = related_entity.get("labels", {}).get("en", {}).get("value", related_qid)
        for url in _wikidata_claim_strings(related_entity, "P856"):
            host = urlparse(url).hostname
            if not host:
                continue
            rd = root_domain(host.lower())
            if rd and rd != seed_root and rd not in sites:
                sites[rd] = f"Wikidata: {rel_label}, a subsidiary/parent of the seed org"
    return sites


def _web_search_sister_domains(session: Any, seed_root: str, brand_tokens: list[str], title: str = "", *, timeout: int = 10):
    """(strong, weak) domain->context maps. Strong = the org's own/parent/
    subsidiary sites from its Wikipedia INFOBOX (owner/parent/subsidiaries/
    website rows — not article citations); weak = a generic search snippet."""
    from bs4 import BeautifulSoup

    tools_dir = Path(__file__).resolve().parent
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))
    from _web_search_cli import search as _ddg_search

    brand = seed_root.split(".")[0]
    strong: dict[str, str] = {}
    weak: dict[str, str] = {}

    def _record(bucket: dict[str, str], rd: str, context: str) -> None:
        if rd and rd != seed_root and rd not in _WIKI_SELF and rd not in bucket:
            bucket[rd] = context

    # Only the infobox, and only specific ROW LABELS — the article body links
    # dozens of unrelated news/citation domains, and even within the infobox a
    # "Traded as" row links the STOCK EXCHANGE's own site (confirmed: Adidas's
    # infobox links boerse-frankfurt.de, Uber's links nyse.com) which is pure
    # noise, not an affiliate. Only rows that name an affiliation relationship
    # are trusted. "Subsidiaries"/"Owner"/"Parent" rows usually link to the
    # OTHER entity's Wikipedia article, not its domain directly — that case is
    # covered by the Wikidata subsidiary/parent chase below, which follows the
    # relationship to the entity's own official-website claim.
    _AFFILIATION_ROW_LABELS = frozenset({
        "website", "websites", "official website", "homepage", "url",
        "owner", "owned by", "parent", "parent company", "parent organisation",
        "parent organization",
    })
    wiki_query = " ".join((title or "").split()[:6]).strip() or seed_root or brand
    infobox = BeautifulSoup(_wikipedia_page(session, wiki_query, timeout=timeout) or "", "html.parser").find("table", class_="infobox")
    if not infobox and wiki_query != brand:
        infobox = BeautifulSoup(_wikipedia_page(session, brand, timeout=timeout) or "", "html.parser").find("table", class_="infobox")
    if infobox:
        all_box_text = infobox.get_text(" ", strip=True).lower()
        is_seed_entity = (
            seed_root in all_box_text
            or any(_shares_brand_token(seed_root, [bt]) and bt in all_box_text for bt in brand_tokens)
        )
        if is_seed_entity:
            for row in infobox.find_all("tr"):
                header = row.find("th")
                label = header.get_text(" ", strip=True).lower() if header else ""
                if label not in _AFFILIATION_ROW_LABELS:
                    continue
                row_text = row.get_text(" ", strip=True).lower()
                for a in row.find_all("a", href=True):
                    host = urlparse(a["href"]).hostname
                    if host:
                        _record(strong, root_domain(host.lower()), f"Wikipedia infobox '{label}' row")
                for match in _DOMAIN_RE.finditer(row_text):
                    _record(strong, root_domain(match.group(1).lower()), f"Wikipedia infobox '{label}' row")

    for query in (
        f"{seed_root} subsidiaries brands affiliated websites",
        f"{brand} official website network of sites",
    ):
        try:
            result = _ddg_search(query, limit=10)
        except Exception as exc:
            logger.info("web_search query failed (%r): %s", query, exc)
            continue
        for row in result.get("results", []):
            context = f"web search {query!r}: {row.get('title', '')[:80]}"
            host = urlparse(row.get("url", "")).hostname
            if host:
                _record(weak, root_domain(host.lower()), context)
            for match in _DOMAIN_RE.finditer(f"{row.get('title', '')} {row.get('snippet', '')}"):
                _record(weak, root_domain(match.group(1).lower()), context)

    strong = {rd: ctx for rd, ctx in strong.items() if _domain_resolves(rd)}
    weak = {rd: ctx for rd, ctx in weak.items() if rd not in strong and _domain_resolves(rd)}
    return strong, weak


def _site_scrape_links(session: Any, seed_root: str, homepage_html: str, base_url: str, *, timeout: int = 12) -> list[str]:
    """Outbound-link apexes from the homepage + its relationship pages (about,
    subsidiaries, partners). Weak evidence — the affiliation gate decides."""
    from bs4 import BeautifulSoup

    def _links(html: str, base: str) -> list[dict[str, str]]:
        out = []
        for a in BeautifulSoup(html, "html.parser").find_all("a", href=True):
            href = a["href"].strip()
            if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                out.append({"url": urljoin(base, href), "text": (a.get_text() or "").strip().lower()})
        return out

    hints = ("subsidiar", "joint-venture", "investor", "group-compan", "our-compan", "affiliat", "partner", "about")
    home_links = _links(homepage_html, base_url)
    rel_pages = [
        link["url"] for link in home_links
        if any(h in urlparse(link["url"]).path.lower() or h in link["text"] for h in hints)
        and (urlparse(link["url"]).hostname or "").lower().endswith(seed_root)
    ]

    all_links = list(home_links)
    for page_url in rel_pages[:6]:
        text, _ = _fetch(session, page_url, timeout=timeout)
        if text:
            all_links.extend(_links(text, page_url))

    apexes: list[str] = []
    for link in all_links:
        host = (urlparse(link["url"]).hostname or "").lower()
        rd = root_domain(host) if host else ""
        if rd and rd != seed_root and not rd.endswith(f".{seed_root}") and rd not in apexes:
            apexes.append(rd)
    return apexes


# --------------------------------------------------------------------------
# Candidate model + confidence
# --------------------------------------------------------------------------
_STRONG_METHODS = frozenset({"reverse_whois", "tracker_pivot", "favicon_hash", "self_infra", "web_search", "wikidata"})


@dataclass
class Candidate:
    domain: str
    methods: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    strong_methods: set[str] = field(default_factory=set)
    weak_methods: set[str] = field(default_factory=set)
    brand_match: bool = False
    live: bool = False

    def add(self, method: str, evidence: str, *, strong: bool) -> None:
        if method not in self.methods:
            self.methods.append(method)
        (self.strong_methods if strong else self.weak_methods).add(method)
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)

    @property
    def score(self) -> int:
        return 40 * len(self.strong_methods) + 15 * len(self.weak_methods) + (10 if self.brand_match else 0)


def candidate_confidence(candidate: Candidate) -> str:
    strong = len(candidate.strong_methods)
    if strong >= 2 or "reverse_whois" in candidate.strong_methods or (strong and candidate.brand_match):
        return "high"
    if strong or (len(candidate.weak_methods) >= 2 and candidate.brand_match):
        return "medium"
    return "low"


# --------------------------------------------------------------------------
# Hunter
# --------------------------------------------------------------------------
class DomainHunter:
    """Sister-domain discovery by same operator / registrant / brand."""

    _ALIASES = {
        "crawl": "site_scrape", "scrape": "site_scrape",
        "dns": "self_infra", "mx": "self_infra", "ns": "self_infra",
        "spf": "self_infra", "dmarc": "self_infra", "spf_dmarc": "self_infra",
        "reverse_ns": "self_infra", "email": "self_infra", "email_pivot": "self_infra",
        "revwhois": "reverse_whois", "rev-whois": "reverse_whois", "whoxy": "reverse_whois",
        "rdap": "reverse_whois", "whois": "reverse_whois",
        "trackers": "tracker_pivot", "ga_pivot": "tracker_pivot",
        "icon": "favicon", "favicon_hash": "favicon",
        "subsidiaries": "wikidata", "parent": "wikidata", "wikidata_chase": "wikidata",
    }
    _DEFAULT = {"site_scrape", "self_infra", "reverse_whois", "tracker_pivot", "web_search", "favicon", "wikidata"}

    def __init__(self, domain: str, *, modules: str = "", confidence_min: str = "low") -> None:
        self.seed_root = hunter_seed_apex(domain)
        self.confidence_min = confidence_min if confidence_min in _CONF_RANK else "low"
        self.modules = self._normalize_modules(modules)
        self.session = _http_session()
        self.candidates: dict[str, Candidate] = {}
        self.brand_tokens: list[str] = _brand_tokens(self.seed_root)
        self.seed_title: str = ""

    @classmethod
    def _normalize_modules(cls, modules: str) -> set[str]:
        if not modules.strip():
            return set(cls._DEFAULT)
        parts = {p.strip().lower() for p in modules.split(",") if p.strip()}
        return {cls._ALIASES.get(p, p) for p in parts}

    def _emit_progress(self, stage: str) -> None:
        print(f"# domain_hunter progress: completed={stage!r} candidates_so_far={len(self.candidates)}")
        emit_findings_snapshot(list(self.candidates.values()))

    def discover(self) -> list[Candidate]:
        if not self.seed_root:
            return []
        stages = (
            ("site_scrape", self._collect_site_signals),
            ("self_infra", self._collect_self_infra_signals),
            ("reverse_whois", self._collect_reverse_whois_signals),
            ("tracker_pivot", self._collect_tracker_pivot_signals),
            ("web_search", self._collect_web_search_signals),
            ("wikidata", self._collect_wikidata_signals),
            ("favicon", self._collect_favicon_signals),
        )
        for name, collector in stages:
            if name in self.modules:
                try:
                    collector()
                except Exception as exc:
                    logger.info("domain_hunter %s failed: %s", name, exc)
                self._emit_progress(name)

        self._resolve_live_status()
        filtered = [c for c in self.candidates.values() if self._passes_confidence_floor(c)]
        filtered.sort(key=lambda c: (-c.score, not c.live, c.domain))
        return filtered

    def _add_candidate(self, domain: str, *, method: str, evidence: str) -> None:
        domain = root_domain(domain)
        if not domain or "." not in domain or not _is_likely_domain_or_none(domain):
            return
        if not self.seed_root or is_same_root(domain, self.seed_root) or _at_psl_private_apex(domain):
            return
        strong = method in _STRONG_METHODS
        brand = _shares_brand_token(domain, self.brand_tokens)
        existing = self.candidates.get(domain)
        # A weak, non-brand signal is only kept if it corroborates a candidate a
        # strong/brand signal already created — never on its own (that is the
        # third-party-provider / unrelated-link noise the old denylists chased).
        if not strong and not brand and existing is None:
            return
        if existing is None:
            existing = Candidate(domain=domain)
            self.candidates[domain] = existing
        if brand:
            existing.brand_match = True
        existing.add(method, evidence, strong=strong)

    def _collect_site_signals(self) -> None:
        homepage, final_url = _fetch_with_fallback(self.session, f"https://{self.seed_root}")
        if not homepage:
            return
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(homepage, "html.parser")
        title = (soup.title.get_text(" ", strip=True) if soup.title else "").strip()
        self.seed_title = title
        self.brand_tokens = _brand_tokens(self.seed_root, title)

        if final_url:
            final_host = root_domain(urlparse(final_url).hostname or "")
            if final_host and final_host != self.seed_root:
                self._add_candidate(final_host, method="site_scrape", evidence=f"redirected to {final_url}")
        for apex in _site_scrape_links(self.session, self.seed_root, homepage, f"https://{self.seed_root}"):
            self._add_candidate(apex, method="site_scrape", evidence=f"outbound link: {apex}")

        for blob, label in (
            (_fetch_with_fallback(self.session, f"https://{self.seed_root}/robots.txt")[0], "robots.txt"),
            (_fetch_with_fallback(self.session, f"https://{self.seed_root}/sitemap.xml")[0], "sitemap.xml"),
        ):
            for domain in _extract_domains(blob or ""):
                self._add_candidate(domain, method="site_scrape", evidence=f"{label} reference: {domain}")

    def _collect_self_infra_signals(self) -> None:
        """Self-hosted mail/DNS infra: an MX/NS/SPF/DMARC apex is a sister only
        when it shares the seed's brand token (geoit.tv), not a provider."""
        hosts: list[tuple[str, str]] = []
        for host in _dns_records(self.seed_root, "NS"):
            hosts.append((host, f"authoritative NS: {host}"))
        for host in _dns_records(self.seed_root, "MX"):
            hosts.append((host, f"MX host: {host}"))
        for inc in _spf_includes(self.seed_root):
            hosts.append((inc, f"SPF include: {inc}"))
        for rua in _dmarc_rua(self.seed_root):
            hosts.append((rua, f"DMARC rua domain: {rua}"))
        for host, evidence in hosts:
            rd = root_domain(host)
            if rd and rd != self.seed_root and _shares_brand_token(rd, self.brand_tokens):
                self._add_candidate(rd, method="self_infra", evidence=evidence)

    def _collect_reverse_whois_signals(self) -> None:
        for rd in _whoxy_reverse_whois(self.session, self.seed_root):
            self._add_candidate(rd, method="reverse_whois", evidence=f"same WHOIS registrant/org as {self.seed_root}")

    def _collect_tracker_pivot_signals(self) -> None:
        for rd in _tracker_id_pivot(self.session, self.seed_root):
            self._add_candidate(rd, method="tracker_pivot", evidence=f"shared analytics/pixel ID with {self.seed_root}")

    def _collect_web_search_signals(self) -> None:
        strong, weak = _web_search_sister_domains(self.session, self.seed_root, self.brand_tokens, self.seed_title)
        for rd, context in strong.items():
            self._add_candidate(rd, method="web_search", evidence=context)
        for rd, context in weak.items():
            self._add_candidate(rd, method="web_mention", evidence=context)

    def _collect_wikidata_signals(self) -> None:
        """Subsidiary/parent sister sites from Wikidata's structured org graph
        (P355/P749 chased to P856) — see _wikidata_affiliated_sites."""
        brand = self.seed_root.split(".")[0]
        for rd, context in _wikidata_affiliated_sites(self.session, self.seed_root, brand, self.seed_title).items():
            self._add_candidate(rd, method="wikidata", evidence=context)

    def _collect_favicon_signals(self) -> None:
        seed_hash = _favicon_md5(self.session, self.seed_root)
        if not seed_hash:
            return
        for candidate in list(self.candidates.values()):
            if candidate.domain != self.seed_root and _favicon_md5(self.session, candidate.domain) == seed_hash:
                candidate.add("favicon_hash", f"identical favicon to {self.seed_root}", strong=True)

    def _resolve_live_status(self) -> None:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        deadline = time.monotonic() + 90.0

        def probe(candidate: Candidate) -> bool:
            return _live_probe(self.session, candidate.domain)[0] if time.monotonic() <= deadline else False

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(probe, c): c for c in self.candidates.values()}
            for future in as_completed(futures):
                try:
                    futures[future].live = future.result()
                except Exception:
                    futures[future].live = False

    def _passes_confidence_floor(self, candidate: Candidate) -> bool:
        return _CONF_RANK[candidate_confidence(candidate)] >= _CONF_RANK[self.confidence_min]


# --------------------------------------------------------------------------
# Output + parsing (DHJSON contract consumed by the backend parser)
# --------------------------------------------------------------------------
def rows_from_candidates(candidates: list[Candidate]) -> list[dict[str, Any]]:
    return [
        {
            "domain": c.domain,
            "method": "; ".join(c.methods) or "unknown",
            "confidence": candidate_confidence(c),
            "live": c.live,
            "score": c.score,
            "evidence": list(c.evidence),
        }
        for c in candidates
    ]


def format_rows(candidates: list[Candidate]) -> str:
    rows = rows_from_candidates(candidates)
    if not rows:
        return ""
    dw = max(6, min(36, max(len(r["domain"]) for r in rows)))
    mw = max(6, min(40, max(len(r["method"]) for r in rows)))
    lines = ["=== Findings ===", f"{'Domain'.ljust(dw)}  {'Method'.ljust(mw)}  Confidence  Live"]
    for r in rows:
        lines.append(f"{r['domain'].ljust(dw)}  {r['method'][:mw].ljust(mw)}  {r['confidence'].ljust(10)}  {'Yes' if r['live'] else 'No'}")
    return "\n".join(lines)


_DHJSON_PREFIX = "# DHJSON "


def emit_findings_snapshot(candidates: list[Candidate]) -> None:
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
            writer.writerow({**row, "live": "yes" if row["live"] else "no", "evidence": " | ".join(row["evidence"])})
    return output


def parse_stdout(stdout: str) -> list[dict[str, Any]]:
    """Prefer the last ``# DHJSON`` line (full fields, including ``[]``); fall
    back to the last ``=== Findings ===`` table for older output."""
    json_blocks: list[list[dict[str, Any]]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith(_DHJSON_PREFIX):
            try:
                data = json.loads(stripped[len(_DHJSON_PREFIX):])
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
        apex = root_domain(str(row.get("domain", "") or "").strip())
        if not apex or apex in seen or not is_registrable_domain(apex):
            continue
        seen.add(apex)
        live = row.get("live")
        live = live.strip().lower() in {"yes", "true", "1"} if isinstance(live, str) else bool(live)
        conf = str(row.get("confidence", "low") or "low").strip().lower()
        normalized.append({
            "domain": apex,
            "method": str(row.get("method", "") or "").strip() or "unknown",
            "confidence": conf if conf in _CONF_RANK else "low",
            "live": live,
            "score": row.get("score"),
            "evidence": row.get("evidence") or [],
        })
    return normalized


def _parse_findings_table(stdout: str) -> list[dict[str, Any]]:
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
        if stripped.startswith("Wrote ") or (stripped.startswith("===") and not stripped.startswith("=== Findings")):
            blocks.append(current)
            current = None
            continue
        if not stripped or stripped == "(none)" or stripped.startswith("Domain "):
            continue
        match = row_re.match(stripped)
        if match:
            current.append({
                "domain": match.group("domain").lower(),
                "method": match.group("method").strip(),
                "confidence": match.group("conf"),
                "live": match.group("live") == "Yes",
            })
    if current is not None:
        blocks.append(current)
    return blocks[-1] if blocks else []


def run_hunter(domain: str, *, modules: str = "", confidence_min: str = "low", output: str = "") -> tuple[list[Candidate], Path | None]:
    hunter = DomainHunter(domain, modules=modules, confidence_min=confidence_min)
    candidates = hunter.discover()
    return candidates, write_output_file(output, candidates)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Discover sister/affiliated root domains.")
    parser.add_argument("--domain", required=True, help="Seed root domain")
    parser.add_argument("--modules", default="", help="Comma-separated module subset")
    parser.add_argument("--confidence-min", default="low", choices=("low", "medium", "high"))
    parser.add_argument("--output", default="", help="Optional CSV or JSON output path")
    args, extra = parser.parse_known_args(argv)

    candidates, output_path = run_hunter(
        args.domain, modules=args.modules, confidence_min=args.confidence_min, output=args.output,
    )
    emit_findings_snapshot(candidates)
    if extra:
        logger.info("Ignored extra args: %s", " ".join(extra))
    print(f"Wrote {len(candidates)} candidate(s)" + (f" to {output_path}" if output_path else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
