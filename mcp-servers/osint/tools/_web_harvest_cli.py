#!/usr/bin/env python3
"""
Website contact harvester — the passive-OSINT *seed*.

Crawls a target website (same registrable domain, shallow BFS) and extracts the
public identity surface it exposes: email addresses, phone numbers, social-media
profile links (with the handle), and person names (from mailto display text,
`author` meta tags and JSON-LD Person/Organization objects).

Keyless, stdlib + requests/bs4/tldextract (already in the Kali image). Output is a
single JSON object on stdout so the backend parser can turn it into typed findings
and the graph can pivot name → email → account.

Usage:
    python3 _web_harvest_cli.py <url> [--depth 1] [--max-pages 25] [--timeout 15]
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from collections import deque
from urllib.parse import unquote, urljoin, urlparse

try:
    import requests
    import tldextract
    from bs4 import BeautifulSoup
except Exception as exc:  # pragma: no cover - environment guard
    print(json.dumps({"error": f"missing dependency: {exc}"}))
    sys.exit(0)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}")
_CFEMAIL_RE = re.compile(r"""data-cfemail=["']([0-9a-fA-F]{8,})["']""")
_PAREN_AT_RE = re.compile(
    r"\b([A-Za-z0-9._%+\-]{1,64})\s*[\(\[]\s*at\s*[\)\]]\s*"
    r"([A-Za-z0-9.\-]+\.[A-Za-z]{2,24})\b",
    re.IGNORECASE,
)
_OBFUSCATED_AT_DOT_RE = re.compile(
    r"\b([A-Za-z0-9._%+\-]{1,64})\s*[\[(]\s*at\s*[\])]\s*"
    r"([A-Za-z0-9.\-]+)\s*[\[(]\s*dot\s*[\])]\s*"
    r"([A-Za-z]{2,24})\b",
    re.IGNORECASE,
)
_ASSET_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js",
)
# International-ish phone numbers: optional +, 8–15 digits with separators.
_PHONE_RE = re.compile(r"(?<![\w.])(\+?\d[\d\s().\-]{7,16}\d)(?![\w])")

# host substring -> social network label
_SOCIAL_HOSTS = {
    "twitter.com": "twitter",
    "x.com": "twitter",
    "facebook.com": "facebook",
    "instagram.com": "instagram",
    "linkedin.com": "linkedin",
    "github.com": "github",
    "youtube.com": "youtube",
    "t.me": "telegram",
    "tiktok.com": "tiktok",
    "medium.com": "medium",
    "reddit.com": "reddit",
    "pinterest.com": "pinterest",
    "mastodon": "mastodon",
    "threads.net": "threads",
}

# generic path segments that are not usernames
_SOCIAL_SKIP = {
    "share", "sharer", "intent", "home", "login", "signup", "about",
    "pages", "groups", "watch", "hashtag", "explore", "help", "legal",
    "features", "pricing", "enterprise", "solutions", "products", "product",
    "docs", "blog", "support", "contact", "careers", "jobs", "team", "search",
    "privacy", "terms", "policies", "security", "status", "sitemap", "company",
    "news", "events", "developers", "developer", "api", "download", "downloads",
    "sponsors", "marketplace", "topics", "collections", "trending", "customer-stories",
}

# Placeholder / example addresses that appear in templates and boilerplate — never
# real contacts. Do NOT treat info/admin/contact/support as fake locals; those
# are the mailboxes organisations actually publish.
_FAKE_LOCALS = {
    "you", "your", "youremail", "yourname", "your-email", "emailaddress",
    "example", "firstname", "lastname", "someone", "somebody",
    "abc", "xyz",
}
_PLACEHOLDER_DOMAINS = {
    "example.com", "example.org", "example.net", "domain.com", "email.com",
    "yourdomain.com", "yoursite.com", "company.com", "test.com", "sentry.io",
    "wixpress.com", "sentry-next.wixpress.com", "acme.com", "edge-security.com",
}


def _decode_cfemail(hexstr: str) -> str:
    try:
        data = bytes.fromhex(hexstr)
    except ValueError:
        return ""
    if len(data) < 2:
        return ""
    key = data[0]
    decoded = bytes(b ^ key for b in data[1:])
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return decoded.decode("latin-1", errors="ignore")


def _normalize_email(addr: str) -> str:
    raw = html.unescape(unquote((addr or "").strip()))
    raw = raw.replace("mailto:", "").split("?", 1)[0]
    return raw.strip().strip("\"'<>.,;:()[]{}").lower()


def _is_placeholder_email(addr: str) -> bool:
    addr = _normalize_email(addr)
    if "@" not in addr:
        return True
    if any(addr.endswith(suf) for suf in _ASSET_SUFFIXES):
        return True
    if ".." in addr:
        return True
    local, _, dom = addr.partition("@")
    if not local or not dom or local in _FAKE_LOCALS:
        return True
    if dom in _PLACEHOLDER_DOMAINS or dom.endswith(".wixpress.com"):
        return True
    if not _EMAIL_RE.fullmatch(addr):
        return True
    return False


def _registrable(host: str) -> str:
    ext = tldextract.extract(host)
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else host.lower()


def _social_from_url(url: str, base_domain: str = "") -> dict | None:
    try:
        p = urlparse(url)
    except ValueError:
        return None
    host = (p.netloc or "").lower().lstrip("www.")
    # A link to the SAME registrable domain we are crawling is site navigation,
    # not an external social profile (this is what produced dozens of bogus
    # "accounts" from a site's own nav/footer menu).
    if base_domain and _registrable(host) == base_domain:
        return None
    for key, net in _SOCIAL_HOSTS.items():
        if key in host:
            segs = [s for s in p.path.split("/") if s]
            handle = ""
            for seg in segs:
                s = seg.lstrip("@").lower()
                if s and s not in _SOCIAL_SKIP and not s.endswith((".php", ".html")):
                    handle = seg.lstrip("@")
                    break
            # A social host with no usable handle (bare domain, or only generic
            # path segments) is a share/marketing link, not a profile — drop it.
            if not handle:
                return None
            return {"network": net, "url": url.split("?")[0], "username": handle}
    return None


def _add_email(addr: str, emails: set[str]) -> None:
    e = _normalize_email(addr)
    if e and not _is_placeholder_email(e):
        emails.add(e)


def _emails_from_html(html_text: str, soup, emails: set[str]) -> None:
    blob = html.unescape(unquote(html_text or ""))
    for hexstr in _CFEMAIL_RE.findall(blob):
        _add_email(_decode_cfemail(hexstr), emails)
    for m in _EMAIL_RE.findall(blob):
        _add_email(m, emails)
    for local, domain in _PAREN_AT_RE.findall(blob):
        _add_email(f"{local}@{domain}", emails)
    for local, host, tld in _OBFUSCATED_AT_DOT_RE.findall(blob):
        _add_email(f"{local}@{host}.{tld}", emails)
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            data = json.loads(script.string or "")
        except (json.JSONDecodeError, TypeError):
            continue
        _emails_from_jsonld(data, emails)
    for meta in soup.find_all("meta"):
        key = (meta.get("name") or meta.get("property") or "").lower()
        if "email" in key or key in ("og:email", "contact"):
            _add_email(meta.get("content") or "", emails)


def _emails_from_jsonld(data, emails: set[str]) -> None:
    if isinstance(data, list):
        for item in data:
            _emails_from_jsonld(item, emails)
        return
    if not isinstance(data, dict):
        return
    val = data.get("email") or data.get("emailAddress")
    if isinstance(val, str):
        _add_email(val, emails)
    elif isinstance(val, list):
        for item in val:
            _add_email(str(item), emails)
    for nested in data.values():
        if isinstance(nested, (dict, list)):
            _emails_from_jsonld(nested, emails)


def _names_from_soup(soup) -> set[str]:
    names: set[str] = set()
    for meta in soup.find_all("meta"):
        if (meta.get("name") or "").lower() in ("author", "article:author"):
            val = (meta.get("content") or "").strip()
            if 3 <= len(val) <= 60 and " " in val:
                names.add(val)
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            data = json.loads(script.string or "")
        except (json.JSONDecodeError, TypeError):
            continue
        for obj in data if isinstance(data, list) else [data]:
            if isinstance(obj, dict) and obj.get("@type") in ("Person",):
                nm = str(obj.get("name") or "").strip()
                if 3 <= len(nm) <= 60:
                    names.add(nm)
    return names


def _harvest_payload(seed, base_domain, seed_status, seen, emails, phones, social, names) -> dict:
    blocked = isinstance(seed_status, int) and seed_status in (401, 403, 429)
    return {
        "seed": seed,
        "domain": base_domain,
        "pages_crawled": len(seen),
        "seed_status": seed_status,
        "blocked": blocked,
        "note": (
            f"Seed returned HTTP {seed_status} — likely WAF/CDN blocked; "
            "results may be incomplete. Try theharvester / crt.sh / gau for this domain."
            if blocked else ""
        ),
        "emails": sorted(emails),
        "phones": sorted(phones),
        "social": list(social.values()),
        "names": sorted(names),
    }


def _emit_snapshot(seed, base_domain, seed_status, seen, emails, phones, social, names) -> None:
    payload = _harvest_payload(seed, base_domain, seed_status, seen, emails, phones, social, names)
    print("# EMAILJSON " + json.dumps(payload), flush=True)


def harvest(seed: str, depth: int, max_pages: int, timeout: int) -> dict:
    if not seed.startswith(("http://", "https://")):
        seed = "https://" + seed
    base_domain = _registrable(urlparse(seed).netloc)

    emails: set[str] = set()
    phones: set[str] = set()
    social: dict[str, dict] = {}
    names: set[str] = set()

    seen: set[str] = set()
    seed_status: object = None  # HTTP status (or error string) of the first fetch
    queue: deque[tuple[str, int]] = deque([(seed, 0)])
    # Realistic desktop-browser UA — reduces trivial 403s from WAFs that block
    # obvious bot user-agents. Still fully passive (GET only, no auth).
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    while queue and len(seen) < max_pages:
        url, d = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            if seed_status is None:
                seed_status = f"error:{type(exc).__name__}"
            continue
        if seed_status is None:
            seed_status = resp.status_code
        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype and "text" not in ctype:
            continue
        html_text = resp.text or ""

        soup = BeautifulSoup(html_text, "html.parser")
        _emails_from_html(html_text, soup, emails)

        text = soup.get_text(" ", strip=True)
        for m in _PHONE_RE.findall(text):
            digits = re.sub(r"\D", "", m)
            if 8 <= len(digits) <= 15:
                phones.add(m.strip())

        names |= _names_from_soup(soup)

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("mailto:"):
                addr = href[7:].split("?")[0]
                _add_email(addr, emails)
                disp = a.get_text(" ", strip=True)
                if 3 <= len(disp) <= 60 and " " in disp and "@" not in disp:
                    names.add(disp)
                continue
            if href.startswith("tel:"):
                phones.add(href[4:].strip())
                continue
            absolute = urljoin(url, href)
            sa = _social_from_url(absolute, base_domain)
            if sa:
                social.setdefault(sa["url"], sa)
                continue
            # enqueue same-domain links for the next depth level
            if d < depth:
                try:
                    if _registrable(urlparse(absolute).netloc) == base_domain and absolute.startswith("http"):
                        queue.append((absolute.split("#")[0], d + 1))
                except ValueError:
                    pass

        # Flush a snapshot so a timeout still leaves parseable EMAIL findings.
        _emit_snapshot(seed, base_domain, seed_status, seen, emails, phones, social, names)

    # Surface WHY a crawl was empty: a 401/403/429 seed status means a WAF/CDN
    # (Akamai/Cloudflare) blocked us, not that the site has no contacts.
    return _harvest_payload(seed, base_domain, seed_status, seen, emails, phones, social, names)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--depth", type=int, default=1)
    ap.add_argument("--max-pages", type=int, default=25)
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()
    result = harvest(args.url, max(0, args.depth), max(1, args.max_pages), max(3, args.timeout))
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
