#!/usr/bin/env python3
"""Shared recon extraction primitives — endpoints, secrets, cloud-storage refs.

Standard-library only (``re`` only), so every worker that imports it still runs
inside the Kali container with no extra dependencies. A worker script run as
``python3 /path/_worker.py`` gets its own directory on ``sys.path[0]``
automatically, so a sibling ``import _recon_extract`` resolves with no path
plumbing.

This module is the single source of truth for the secret / endpoint / cloud
pattern sets that ``_js_recon_cli.py`` (JavaScript recon) and
``_app_recon_cli.py`` (mobile/desktop app recon) both mine. Keeping one copy
means a new secret pattern is learned once and both recon surfaces benefit —
previously the JS worker owned the only copy.

Nothing here decides impact: a hit is a FACT that a pattern matched some text,
never a verdict that a secret is valid or an endpoint is vulnerable. The
platform's confidence pipeline earns findings from these facts later.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# LinkFinder-style endpoint regex (relative paths, api routes, absolute urls).
# ---------------------------------------------------------------------------
ENDPOINT_RE = re.compile(
    r"""(?:"|')(
      ((?:[a-zA-Z][a-zA-Z0-9+.\-]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})
      |((?:/|\.\./|\./)[^"'><,;|*()%$^/\\\[\]][^"'><,;|()]{1,})
      |([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:\.(?:php|asp|aspx|jsp|json|js|xml|action|do|html))?(?:\?[^"']{0,})?)
      |([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|do|xml)(?:\?[^"']{0,})?)
    )(?:"|')""",
    re.VERBOSE,
)

# Interesting endpoint markers so we surface the security-relevant ones first.
INTERESTING = (
    "/api", "/v1", "/v2", "/graphql", "/admin", "/auth", "/login", "/token",
    "/oauth", "/user", "/account", "/upload", "/internal", "/private", "/debug",
    "/actuator", "/swagger", "/openapi", "/.env", "/config", "/secret", "/key",
)

# ---------------------------------------------------------------------------
# Secret patterns. (name, compiled regex, high_signal). Ordered specific->generic.
# Placeholder guard filters obvious template/example values.
# ---------------------------------------------------------------------------
SECRET_PATTERNS: list[tuple[str, re.Pattern, bool]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"), True),
    ("aws_secret_access_key", re.compile(r"(?i)aws.{0,20}?(?:secret|key).{0,4}['\"]([0-9a-zA-Z/+]{40})['\"]"), True),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), True),
    ("sendgrid_api_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{16,64}\b"), True),
    ("mailchimp_api_key", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"), True),
    ("square_access_token", re.compile(r"\b(?:sq0atp|sq0csp|EAAA)[0-9A-Za-z\-_]{22,}\b"), True),
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

PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|your[_-]?|xxxx+|placeholder|dummy|test[_-]?key|changeme|"
    r"redacted|<[^>]+>|\{\{|\}\}|0{10,}|null|undefined)"
)

# ---------------------------------------------------------------------------
# Cloud storage exposure.
# ---------------------------------------------------------------------------
CLOUD_PATTERNS: list[tuple[str, re.Pattern]] = [
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

_ASSET_NOISE_RE = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|map|mp4|webp)(\?|$)", re.I
)

# Bare absolute URL (not quote-anchored). The endpoint regex above is
# LinkFinder-style and only fires on quoted strings — right for JavaScript,
# but app packages carry many *unquoted* URLs (compiled into native binaries,
# .properties/.plist config, strings tables). This catches those.
#
# The character class deliberately excludes ASCII control bytes, the C1 range,
# and the Unicode replacement char: when a binary blob (a compiled AXML/arsc
# string pool, a .dex) is decoded as text, a greedy class would let a URL run
# on across the surrounding framing bytes, producing one giant garbage
# "endpoint" and massively inflating output. A URL never legitimately contains
# those bytes, so excluding them keeps the match to the real URL.
_BARE_URL_RE = re.compile(
    r"\bhttps?://[^\s\"'<>()\[\]{}|\\^`\x00-\x1f\x7f-\x9f�]+", re.I
)
_HOSTNAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)

# Any control byte, C1 control, or the Unicode replacement char. A real
# endpoint/URL/secret never contains these — their presence means the match
# spanned binary framing, so the whole token is junk and is dropped.
_JUNK_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f�]")


_WS_RE = re.compile(r"\s")


def _is_clean(token: str) -> bool:
    return not _JUNK_CHARS_RE.search(token)


def sanitize_text(text: str) -> str:
    """Replace runs of non-printable/binary bytes (control, C1, replacement
    char) with a newline so an extractor token can never span binary framing.

    Keeps tab/newline/carriage-return. Callers that mine text recovered from
    binary containers (compiled resources, string pools) should run this first;
    the extractors below also reject any junk-bearing token as a second line of
    defense, so a caller that forgets is still safe, just noisier.
    """
    return _JUNK_CHARS_RE.sub("\n", text or "")


def extract_endpoints(text: str) -> list[str]:
    """Return endpoint/URL-like strings found in ``text`` (asset noise dropped)."""
    out: list[str] = []
    for m in ENDPOINT_RE.finditer(text):
        ep = m.group(1).strip()
        if not ep or len(ep) > 300:
            continue
        # A path/URL never contains raw whitespace — a match that does spanned
        # a newline the quote-anchored regex allowed through (common once binary
        # framing has been turned into newlines by sanitize_text). Drop it.
        if _ASSET_NOISE_RE.search(ep) or not _is_clean(ep) or _WS_RE.search(ep):
            continue
        out.append(ep)
    return out


def extract_secrets(text: str, source: str) -> list[dict]:
    """Return hardcoded-secret hits (template/placeholder values filtered out)."""
    found: list[dict] = []
    for name, pat, high in SECRET_PATTERNS:
        for m in pat.finditer(text):
            value = m.group(0)
            captured = m.group(m.lastindex) if m.lastindex else value
            if PLACEHOLDER_RE.search(captured) or not _is_clean(value):
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


def extract_cloud(text: str, source: str) -> list[dict]:
    """Return cloud-storage (S3/GCS/Azure/DO) references found in ``text``."""
    out: list[dict] = []
    for name, pat in CLOUD_PATTERNS:
        for m in pat.finditer(text):
            out.append({"type": name, "bucket": m.group(1), "match": m.group(0)[:120], "source": source})
    return out


def extract_urls(text: str) -> list[str]:
    """Return bare (unquoted) absolute http/https URLs found in ``text``."""
    out: list[str] = []
    for m in _BARE_URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:)\"'")
        if len(url) > 500 or _ASSET_NOISE_RE.search(url) or not _is_clean(url):
            continue
        out.append(url)
    return out


def host_of(url: str) -> str:
    """Hostname of an absolute/scheme-relative URL, or '' if not host-shaped."""
    m = re.match(r"(?:[a-z][a-z0-9+.\-]*:)?//([^/:\s\"']+)", url, re.I)
    if not m:
        return ""
    host = m.group(1).split("@")[-1].split(":")[0].strip().lower()
    return host if _HOSTNAME_RE.match(host) else ""


def is_interesting(endpoint: str) -> bool:
    low = endpoint.lower()
    return any(m in low for m in INTERESTING)


def dedupe_secrets(secrets: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for s in secrets:
        k = (s["type"], s["secret"])
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def dedupe_cloud(cloud: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for c in cloud:
        k = (c["type"], c["bucket"])
        if k in seen:
            continue
        seen.add(k)
        out.append(c)
    return out
