"""Email extraction, normalization, and validation for OSINT harvest tools.

Used by theharvester / web_contact_harvest parsers so EMAIL findings are minted
from real addresses, not tool banners, image filenames, or template domains.
"""

from __future__ import annotations

import json
import re
from html import unescape
from urllib.parse import unquote, urlparse

# Conservative RFC-ish mailbox. TLD must be letters (rejects npm ``pkg@1.2.3``).
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_EMAILJSON_PREFIX = "# EMAILJSON "

# ``local [at] domain [dot] tld`` / ``local(at)domain.com`` — not English "look at".
_OBFUSCATED_AT_DOT_RE = re.compile(
    r"\b([A-Za-z0-9._%+\-]{1,64})\s*[\[(]\s*at\s*[\])]\s*"
    r"([A-Za-z0-9.\-]+)\s*[\[(]\s*dot\s*[\])]\s*"
    r"([A-Za-z]{2,24})\b",
    re.IGNORECASE,
)
_PAREN_AT_RE = re.compile(
    r"\b([A-Za-z0-9._%+\-]{1,64})\s*[\(\[]\s*at\s*[\)\]]\s*"
    r"([A-Za-z0-9.\-]+\.[A-Za-z]{2,24})\b",
    re.IGNORECASE,
)
_DOT_TOKEN_RE = re.compile(r"\s*(?:\[\s*|\(\s*)?dot(?:\s*\]|\s*\))?\s*", re.IGNORECASE)

_ASSET_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf",
)

# Template / disposable / tool-artifact mailbox hosts. ``info@acme.com`` is NOT
# in here — that is a typical real contact address.
_BLOCKED_DOMAIN_RE = re.compile(
    r"(?:^|\.)("
    r"example\.(?:com|org|net|co|io)|yourdomain\.(?:com|net|org)|"
    r"domain\.com|email\.com|site\.com|sentry\.io|domain\.invalid|"
    r"test\.com|sample\.com|mailinator\.com|yopmail\.com|"
    r"wixpress\.com|squarespace\.com|mysite\.com|yoursite\.com|"
    r"company\.com|acme\.(?:com|org)|name\.com|"
    r"user\.com|admin\.com|info\.com|contact\.com|someone\.com|"
    r"edge-security\.com|localhost|local$"
    r")$"
)

# Locals that are template copy, never a published contact — do NOT include
# info/admin/contact/support/sales (those are the useful harvest).
_FAKE_LOCALS = frozenset({
    "you", "your", "youremail", "yourname", "your-email", "emailaddress",
    "example", "firstname", "lastname", "someone", "somebody",
    "user@example", "name", "email", "username", "abc", "xyz",
})

_TOOL_ARTIFACT_EMAILS = frozenset({
    "cmartorella@edge-security.com",
})

_CFEMAIL_RE = re.compile(
    r"""data-cfemail=["']([0-9a-fA-F]{8,})["']""",
)


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


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


def normalize_email(candidate: str) -> str:
    """Lowercase, trim wrappers/whitespace, unescape HTML and mailto encoding."""
    raw = unescape(unquote((candidate or "").strip()))
    raw = raw.replace("mailto:", "").split("?", 1)[0]
    raw = raw.strip().strip("\"'<>.,;:()[]{}").strip()
    raw = _DOT_TOKEN_RE.sub(".", raw)
    return raw.lower()


def is_valid_email(candidate: str) -> bool:
    """True only for a real-looking contact address — not placeholders or assets."""
    addr = normalize_email(candidate)
    if not addr or len(addr) > 254 or "@" not in addr:
        return False
    if "email protected" in addr:
        return False
    if any(addr.endswith(suf) for suf in _ASSET_SUFFIXES):
        return False
    if addr in _TOOL_ARTIFACT_EMAILS:
        return False
    if ".." in addr or addr.startswith(".") or addr.endswith("."):
        return False
    local, _, domain = addr.partition("@")
    if not local or not domain or local.startswith(".") or local.endswith("."):
        return False
    if domain.startswith("-") or domain.endswith("-") or domain.startswith("."):
        return False
    if local in _FAKE_LOCALS:
        return False
    if not EMAIL_RE.fullmatch(addr):
        return False
    if _BLOCKED_DOMAIN_RE.search(domain):
        return False
    return True


def _collect_obfuscated(text: str, found: list[str], seen: set[str]) -> None:
    for local, domain in _PAREN_AT_RE.findall(text):
        _add(f"{local}@{domain}", found, seen)
    for local, host, tld in _OBFUSCATED_AT_DOT_RE.findall(text):
        _add(f"{local}@{host}.{tld}", found, seen)


def _add(candidate: str, found: list[str], seen: set[str]) -> None:
    addr = normalize_email(candidate)
    if not is_valid_email(addr) or addr in seen:
        return
    seen.add(addr)
    found.append(addr)


def extract_emails(text: str) -> list[str]:
    """Ordered unique valid emails from free text, HTML, or tool banners."""
    if not text:
        return []
    blob = unescape(unquote(strip_ansi(text)))
    found: list[str] = []
    seen: set[str] = set()
    for hexstr in _CFEMAIL_RE.findall(blob):
        _add(_decode_cfemail(hexstr), found, seen)
    for match in EMAIL_RE.findall(blob):
        _add(match, found, seen)
    _collect_obfuscated(blob, found, seen)
    return found


def emails_from_json_value(value: object) -> list[str]:
    """Normalize a JSON emails field (strings, dicts, mixed)."""
    found: list[str] = []
    seen: set[str] = set()

    def walk(item: object) -> None:
        if item is None:
            return
        if isinstance(item, str):
            _add(item, found, seen)
            return
        if isinstance(item, dict):
            for key in ("email", "mail", "address", "value"):
                if item.get(key):
                    walk(item.get(key))
            return
        if isinstance(item, (list, tuple, set)):
            for el in item:
                walk(el)

    walk(value)
    return found


def extract_harvest_json(stdout: str) -> dict | None:
    """Last complete harvest JSON object in stdout (final dump or # EMAILJSON snapshots)."""
    text = strip_ansi(stdout or "")
    last: dict | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(_EMAILJSON_PREFIX):
            try:
                obj = json.loads(stripped[len(_EMAILJSON_PREFIX):])
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(obj, dict):
                last = obj
    if last is not None:
        return last
    trimmed = text.strip()
    if trimmed.startswith("{") and trimmed.endswith("}"):
        try:
            obj = json.loads(trimmed)
            if isinstance(obj, dict):
                return obj
        except (json.JSONDecodeError, ValueError):
            pass
    decoder = json.JSONDecoder()
    best: dict | None = None
    for idx, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _end = decoder.raw_decode(text, idx)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict) and (
            "emails" in obj or "hosts" in obj or "domain" in obj or "interesting_urls" in obj
        ):
            best = obj
    return best


def email_domain(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].strip().lower()


def matches_target_domain(addr: str, target: str) -> bool:
    """True when the mailbox host is the target or a subdomain of it."""
    host = email_domain(addr)
    seed = (target or "").strip().lower()
    if not host or not seed:
        return False
    if "://" in seed:
        seed = (urlparse(seed).hostname or seed).lower()
    seed = seed.split("/")[0].split(":")[0].lstrip("www.")
    if not seed or "." not in seed:
        return False
    return host == seed or host.endswith("." + seed)
