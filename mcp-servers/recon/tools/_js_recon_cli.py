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
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
_MAX_JS_BYTES = 3_000_000  # 3 MB per script cap
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


# ---------------------------------------------------------------------------
# LinkFinder-style endpoint regex (relative paths, api routes, absolute urls).
# ---------------------------------------------------------------------------
_ENDPOINT_RE = re.compile(
    r"""(?:"|')(
      ((?:[a-zA-Z][a-zA-Z0-9+.\-]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})
      |((?:/|\.\./|\./)[^"'><,;|*()%$^/\\\[\]][^"'><,;|()]{1,})
      |([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:\.(?:php|asp|aspx|jsp|json|js|xml|action|do|html))?(?:\?[^"']{0,})?)
      |([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|do|xml)(?:\?[^"']{0,})?)
    )(?:"|')""",
    re.VERBOSE,
)

# Interesting endpoint markers so we surface the security-relevant ones first.
_INTERESTING = (
    "/api", "/v1", "/v2", "/graphql", "/admin", "/auth", "/login", "/token",
    "/oauth", "/user", "/account", "/upload", "/internal", "/private", "/debug",
    "/actuator", "/swagger", "/openapi", "/.env", "/config", "/secret", "/key",
)

# ---------------------------------------------------------------------------
# Secret patterns. (name, compiled regex, high_signal). Ordered specific->generic.
# Placeholder guard filters obvious template/example values.
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list[tuple[str, re.Pattern, bool]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"), True),
    ("aws_secret_access_key", re.compile(r"(?i)aws.{0,20}?(?:secret|key).{0,4}['\"]([0-9a-zA-Z/+]{40})['\"]"), True),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), True),
    ("google_oauth_client", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), False),
    ("firebase_cloud_messaging", re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"), True),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), True),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"), True),
    ("stripe_secret_key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"), True),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), True),
    ("gitlab_token", re.compile(r"\bglpat-[0-9A-Za-z\-_]{20,}\b"), True),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), False),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), True),
    ("mailgun_key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), True),
    ("twilio_sid", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), True),
    ("authorization_bearer", re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-.=]{20,}"), False),
    ("generic_secret_assignment", re.compile(
        r"(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)"
        r"['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_=./+]{12,64})['\"]"), False),
]

_PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|your[_-]?|xxxx+|placeholder|dummy|test[_-]?key|changeme|"
    r"redacted|<[^>]+>|\{\{|\}\}|0{10,}|null|undefined)"
)

# ---------------------------------------------------------------------------
# Cloud storage exposure.
# ---------------------------------------------------------------------------
_CLOUD_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("s3_bucket_url", re.compile(r"\b([a-z0-9][a-z0-9.\-]{1,61})\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com")),
    # Path-style only: reject the virtual-hosted form (bucket.s3...) via lookbehind
    # so we don't capture the object path of an s3_bucket_url hit as a "bucket".
    ("s3_path_url", re.compile(r"(?<![.a-z0-9\-])s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61})")),
    ("s3_uri", re.compile(r"\bs3://([a-z0-9][a-z0-9.\-]{1,61})")),
    ("gcs_bucket", re.compile(r"\bstorage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61})")),
    ("gcs_bucket_alt", re.compile(r"\b([a-z0-9][a-z0-9._\-]{1,61})\.storage\.googleapis\.com")),
    ("azure_blob", re.compile(r"\b([a-z0-9]{3,24})\.blob\.core\.windows\.net")),
    ("digitalocean_space", re.compile(r"\b([a-z0-9][a-z0-9.\-]{1,61})\.digitaloceanspaces\.com")),
]


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


def _extract_endpoints(text: str) -> list[str]:
    out: list[str] = []
    for m in _ENDPOINT_RE.finditer(text):
        ep = m.group(1).strip()
        if not ep or len(ep) > 300:
            continue
        # Drop pure asset noise.
        if re.search(r"\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|map|mp4|webp)(\?|$)", ep, re.I):
            continue
        out.append(ep)
    return out


def _extract_secrets(text: str, source: str) -> list[dict]:
    found: list[dict] = []
    for name, pat, high in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            value = m.group(0)
            captured = m.group(m.lastindex) if m.lastindex else value
            if _PLACEHOLDER_RE.search(captured):
                continue
            if name == "generic_secret_assignment" and captured.isdigit():
                continue
            found.append({
                "type": name,
                "match": value[:80],
                "secret": captured[:80],
                "high_signal": high,
                "source": source,
            })
    return found


def _extract_cloud(text: str, source: str) -> list[dict]:
    out: list[dict] = []
    for name, pat in _CLOUD_PATTERNS:
        for m in pat.finditer(text):
            out.append({"type": name, "bucket": m.group(1), "match": m.group(0)[:120], "source": source})
    return out


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
    seen_s: set[tuple] = set()
    uniq_secrets = []
    for s in secrets:
        k = (s["type"], s["secret"])
        if k in seen_s:
            continue
        seen_s.add(k)
        uniq_secrets.append(s)
    seen_c: set[tuple] = set()
    uniq_cloud = []
    for c in cloud:
        k = (c["type"], c["bucket"])
        if k in seen_c:
            continue
        seen_c.add(k)
        uniq_cloud.append(c)

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
