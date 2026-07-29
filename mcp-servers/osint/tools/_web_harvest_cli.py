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
import json
import re
import sys
from collections import deque
from urllib.parse import urljoin, urlparse

try:
    import requests
    import tldextract
    from bs4 import BeautifulSoup
except Exception as exc:  # pragma: no cover - environment guard
    print(json.dumps({"error": f"missing dependency: {exc}"}))
    sys.exit(0)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
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
# real contacts. Matched against the local-part and the domain.
_PLACEHOLDER_LOCALS = {
    "you", "your", "youremail", "yourname", "email", "name", "user", "username",
    "example", "test", "demo", "info", "someone", "somebody", "firstname",
    "lastname", "first", "last", "abc", "xyz", "sentry",
}
_PLACEHOLDER_DOMAINS = {
    "example.com", "example.org", "example.net", "domain.com", "email.com",
    "yourdomain.com", "yoursite.com", "company.com", "test.com", "sentry.io",
    "wixpress.com", "sentry-next.wixpress.com",
}


def _is_placeholder_email(addr: str) -> bool:
    addr = addr.lower()
    if "@" not in addr:
        return True
    local, _, dom = addr.partition("@")
    if dom in _PLACEHOLDER_DOMAINS:
        return True
    if local in _PLACEHOLDER_LOCALS:
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


def harvest(seed: str, depth: int, max_pages: int, timeout: int) -> dict:
    if not seed.startswith(("http://", "https://")):
        seed = "https://" + seed
    base_domain = _registrable(urlparse(seed).netloc)

    emails: set[str] = set()
    phones: set[str] = set()
    social: dict[str, dict] = {}
    names: set[str] = set()

    seen: set[str] = set()
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
        except requests.RequestException:
            continue
        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype and "text" not in ctype:
            continue
        html = resp.text or ""

        for m in _EMAIL_RE.findall(html):
            e = m.lower()
            if e.endswith((".png", ".jpg", ".gif", ".svg", ".webp")):
                continue
            if _is_placeholder_email(e):
                continue
            emails.add(e)

        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(" ", strip=True)
        for m in _PHONE_RE.findall(text):
            digits = re.sub(r"\D", "", m)
            if 8 <= len(digits) <= 15:
                phones.add(m.strip())

        names |= _names_from_soup(soup)

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("mailto:"):
                addr = href[7:].split("?")[0].strip().lower()
                if _EMAIL_RE.fullmatch(addr) and not _is_placeholder_email(addr):
                    emails.add(addr)
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

    return {
        "seed": seed,
        "domain": base_domain,
        "pages_crawled": len(seen),
        "emails": sorted(emails),
        "phones": sorted(phones),
        "social": list(social.values()),
        "names": sorted(names),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--depth", type=int, default=1)
    ap.add_argument("--max-pages", type=int, default=25)
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()
    result = harvest(args.url, max(0, args.depth), max(1, args.max_pages), max(3, args.timeout))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
