"""Free web search via DuckDuckGo's no-JS HTML endpoint — no API key, no cost.

Same mechanism the free tier of most open-source agent CLIs use (DuckDuckGo's
html.duckduckgo.com renders results server-side with no JS, so a plain HTTP GET
+ regex extraction works without a browser or a paid search API). Not an MCP
tool — underscore-prefixed, mirrors _shodan_cli.py's shape.
"""

from __future__ import annotations

import json
import re
import sys
from html import unescape
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote_plus, urlparse
from urllib.request import Request, urlopen

_ENDPOINT = "https://html.duckduckgo.com/html/"
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# result__a wraps the title+href, result__snippet the description — DuckDuckGo's
# HTML endpoint has kept these class names stable for years (it's the same
# fallback markup screen-reader/no-JS users get), but if they ever drift this
# degrades to zero results rather than crashing.
_RESULT_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.S
)
_SNIPPET_RE = re.compile(
    r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.S
)
_TAG_RE = re.compile(r"<[^>]+>")


def _clean(text: str) -> str:
    return unescape(_TAG_RE.sub("", text)).strip()


def _unwrap(href: str) -> str:
    """DuckDuckGo wraps result links as //duckduckgo.com/l/?uddg=<real-url>&..."""
    if "uddg=" not in href:
        return href
    parsed = urlparse(href if href.startswith("http") else f"https:{href}")
    qs = parse_qs(parsed.query)
    real = qs.get("uddg", [""])[0]
    return real or href


def search(query: str, limit: int = 10) -> dict[str, Any]:
    """Raises RuntimeError on failure — a normal exception, not SystemExit,
    since this is imported and called directly as a library function (e.g.
    by _domain_hunter_cli.py's web_search module) as well as run as a CLI;
    SystemExit doesn't inherit from Exception, so a library caller's
    `except Exception` around this call would never catch it and the error
    would crash the whole caller instead of being handled per-query. main()
    below is the only place this becomes a process exit code."""
    limit = max(1, min(int(limit), 25))
    url = f"{_ENDPOINT}?q={quote_plus(query)}"
    req = Request(url, headers={"User-Agent": _UA})
    try:
        with urlopen(req, timeout=30) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        raise RuntimeError(f"DuckDuckGo HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"web search network failure: {exc}") from exc

    titles_hrefs = _RESULT_RE.findall(body)
    snippets = _SNIPPET_RE.findall(body)
    rows = []
    for i, (href, title_html) in enumerate(titles_hrefs[:limit]):
        rows.append(
            {
                "title": _clean(title_html),
                "url": _unwrap(href),
                "snippet": _clean(snippets[i]) if i < len(snippets) else "",
            }
        )

    # DuckDuckGo answers a soft-block/anti-bot challenge with HTTP 202 and a
    # page carrying none of the normal result markup — indistinguishable from
    # "genuinely zero matches" by response shape alone unless we check for
    # this specifically. Surfaced as a hard failure (nonzero exit) rather than
    # a quiet empty result: `web_search`'s caller runs with use_recovery=True,
    # so this lets the existing retry/backoff framework actually retry it,
    # and if retries exhaust, the error message says WHY instead of looking
    # like "no results found" for a query that plainly should have some.
    if not rows and status == 202:
        raise RuntimeError(
            "DuckDuckGo rate-limited/challenged this request (HTTP 202, no "
            "result markup) — likely too many searches in a short window. "
            "Not a genuine zero-results query; wait before retrying."
        )

    return {"query": query, "returned": len(rows), "results": rows}


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("Usage: _web_search_cli.py <query> [limit]", file=sys.stderr)
        raise SystemExit(2)
    query = argv[0]
    limit = int(argv[1]) if len(argv) > 1 else 10
    try:
        result = search(query, limit)
    except RuntimeError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
