#!/usr/bin/env python3
"""JS reconnaissance worker — endpoint + secret + cloud-asset extraction.

Fetches a target page, discovers its JavaScript (external <script src> + inline),
downloads each script, and mines it for:
  * endpoints / API paths (LinkFinder-style relative + absolute references)
  * hardcoded secrets (API keys, tokens, JWTs, private keys — gitleaks-style)
  * exposed cloud storage (S3 / GCS / Azure blob URLs)

Standard-library only (urllib / re / json / concurrent.futures) so it runs in
the Kali container with no extra dependencies. Emits a single JSON object on
stdout for the platform parser. This is intentionally a real analysis tool, not
a wrapper around a crawler — endpoint+secret extraction from JS is a first-class
recon capability for modern SPA/API targets.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import ssl
import sys
from urllib.parse import urljoin
from urllib.request import Request, urlopen

# Endpoint / secret / cloud pattern sets + extractors are shared with
# _app_recon_cli.py — a worker's own directory is on sys.path[0], so this
# sibling import resolves inside the Kali container with no path plumbing.
from _recon_extract import (
    INTERESTING as _INTERESTING,
    dedupe_cloud as _dedupe_cloud,
    dedupe_secrets as _dedupe_secrets,
    extract_cloud as _extract_cloud,
    extract_endpoints as _extract_endpoints,
    extract_secrets as _extract_secrets,
)

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
_MAX_JS_BYTES = 3_000_000  # 3 MB per script cap
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _fetch(url: str, timeout: int) -> tuple[str, str]:
    """Return (final_url, body) or ('', '') on failure. Caps body size."""
    try:
        req = Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
        with urlopen(req, timeout=timeout, context=_CTX) as resp:
            raw = resp.read(_MAX_JS_BYTES)
            final = resp.geturl()
        return final, raw.decode("utf-8", "replace")
    except Exception:
        return "", ""


_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)


def _discover_scripts(page_url: str, html: str, timeout: int) -> tuple[list[str], list[str]]:
    """From an HTML page, return (external_js_urls, inline_script_blobs)."""
    external: list[str] = []
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = m.group(1).strip()
        if not src or src.startswith("data:"):
            continue
        external.append(urljoin(page_url, src))
    inline = [m.group(1) for m in _INLINE_SCRIPT_RE.finditer(html) if m.group(1).strip()]
    return list(dict.fromkeys(external)), inline


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="Page URL, JS URL, or comma/newline list of JS URLs")
    ap.add_argument("--max-files", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    raw_targets = [t.strip() for t in re.split(r"[,\n]", args.target) if t.strip()]
    js_urls: list[str] = []
    inline_blobs: list[tuple[str, str]] = []

    for tgt in raw_targets:
        url = tgt if tgt.startswith(("http://", "https://")) else "https://" + tgt
        if url.lower().split("?")[0].endswith(".js"):
            js_urls.append(url)
            continue
        # HTML page — discover its scripts.
        final, body = _fetch(url, args.timeout)
        if not body:
            continue
        ext, inline = _discover_scripts(final or url, body, args.timeout)
        js_urls.extend(ext)
        inline_blobs.extend((f"{url}#inline{i}", b) for i, b in enumerate(inline))

    js_urls = list(dict.fromkeys(js_urls))[: args.max_files]

    endpoints: set[str] = set()
    secrets: list[dict] = []
    cloud: list[dict] = []
    fetched: list[str] = []

    def _work(u: str) -> tuple[str, str]:
        _, body = _fetch(u, args.timeout)
        return u, body

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(_work, js_urls))

    for source, body in list(results) + inline_blobs:
        if not body:
            continue
        fetched.append(source)
        for ep in _extract_endpoints(body):
            endpoints.add(ep)
        secrets.extend(_extract_secrets(body, source))
        cloud.extend(_extract_cloud(body, source))

    # Rank endpoints: interesting first, then alpha.
    ranked = sorted(
        endpoints,
        key=lambda e: (0 if any(m in e.lower() for m in _INTERESTING) else 1, e.lower()),
    )
    # De-dupe secrets/cloud by (type, value).
    uniq_secrets = _dedupe_secrets(secrets)
    uniq_cloud = _dedupe_cloud(cloud)

    print(json.dumps({
        "target": args.target,
        "js_files_analyzed": fetched,
        "js_file_count": len(fetched),
        "endpoints": ranked[:800],
        "endpoint_count": len(ranked),
        "secrets": uniq_secrets,
        "cloud_assets": uniq_cloud,
    }, indent=None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
