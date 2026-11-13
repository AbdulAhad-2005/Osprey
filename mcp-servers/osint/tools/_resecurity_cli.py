"""Shared Resecurity credential-intel REST helper (not an MCP tool — underscore-prefixed).

Resecurity's API has no self-serve public docs — the contract below was
confirmed live against the Breaches API (one of several products under
https://app.resecurity.com/doc/*-api, each requiring an actual portal login to
view). It's kept *configurable* since other accounts/products may differ:

    RESECURITY_API_KEY        (required)  your API key
    RESECURITY_API_BASE       default https://app.resecurity.com/api
    RESECURITY_ENDPOINT       default /breaches/index     (path to hit)
    RESECURITY_QUERY_PARAM    default query               (query-string param name)
    RESECURITY_AUTH_HEADER    default Authorization       (header carrying the key)
    RESECURITY_AUTH_SCHEME    default Basic                 — confirmed: HTTP Basic
                              with the API key as the username, empty password
                              (the server advertises `WWW-Authenticate: Basic`).
                              Any other value is sent literally as "<SCHEME> <key>"
                              (e.g. Bearer); "" for a bare key with no scheme word.
    RESECURITY_PAGE_SIZE_PARAM  default per-page           (Yii2 pagination;
                              NOT "limit" — confirmed via X-Pagination-* response
                              headers; a wrong name is silently ignored by the
                              server, capped at 20/page).

Response is a flat JSON array of breach records (id, email, username, password,
password_hash, source: {name, add_date, compromised_data, ...}, info: {...}),
not an object — `_extract` walks it for credential-shaped records (email/
username + password/password_hash) and loose emails, so the backend
`parse_resecurity` gets typed CREDENTIAL / EMAIL findings regardless of shape
drift. Leaked creds are stored intact (offensive) and graded as INFERRED leads.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
_PASSWORD_KEYS = ("password", "pass", "passwd", "secret")
_HASH_KEYS = ("password_hash", "passwordhash", "hash")
_USER_KEYS = ("username", "user", "login", "account")


def _cfg(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _cfg_or_unset(name: str) -> str | None:
    """Like `_cfg` but distinguishes "not set" (None) from "set to empty" ("")
    — `_cfg`'s `or default` can't tell them apart, so RESECURITY_AUTH_SCHEME="",
    the documented way to get a bare key header with no scheme prefix, could
    never actually take effect."""
    val = os.environ.get(name)
    return val.strip() if val is not None else None


def _api_key() -> str:
    key = _cfg("RESECURITY_API_KEY")
    if not key:
        raise SystemExit(
            "ERROR: RESECURITY_API_KEY is not set. Add it (and optionally "
            "RESECURITY_API_BASE / RESECURITY_ENDPOINT for your account) to .env "
            "and restart kali-tools/backend."
        )
    return key


def _diagnose_http_error(code: int, detail: str, endpoint: str) -> str:
    """Resecurity's gateway (Yii2) returns {"previous":{"name":"Invalid
    Route",...}} for a path that doesn't exist on this product/account at all —
    a different product (e.g. a Monitor-only key) uses different paths than the
    confirmed Breaches API default. Name it so a wrong RESECURITY_ENDPOINT
    doesn't read as a generic/auth failure."""
    if '"Invalid Route"' in detail or "Unable to resolve the request" in detail:
        return (
            f"ERROR: Resecurity rejected the path {endpoint!r} as an unknown route "
            f"(HTTP {code}). This account's API uses a different path shape — get "
            "the real endpoint from your Resecurity account's API reference/support "
            "and set RESECURITY_ENDPOINT (and RESECURITY_QUERY_PARAM if needed) in "
            f".env. Raw response: {detail}"
        )
    if code in (401, 403):
        return (
            f"ERROR: Resecurity rejected the request as unauthorized (HTTP {code}). "
            "Check RESECURITY_API_KEY is correct for THIS product (the Breaches API "
            "default sends it as HTTP Basic with the key as username — a key issued "
            "for a different Resecurity product, e.g. Monitor/Cards, may need a "
            f"different RESECURITY_ENDPOINT too). Raw response: {detail}"
        )
    return f"ERROR: Resecurity HTTP {code}: {detail}"


def _source_name(value: Any) -> str:
    """The confirmed Breaches API nests the breach under source: {name, ...} —
    a dict, not a flat string. Fall back to a flat source/database/breach field
    for other Resecurity products/shapes."""
    if isinstance(value, dict):
        return str(value.get("name") or "")
    return str(value or "")


def _source_date(value: Any) -> str:
    """source.add_date → ISO date, so a filed finding can say when the breach
    was recorded instead of always "unknown". The official schema declares it
    as string($date), but live responses return a bare unix-timestamp int —
    accept either."""
    if not isinstance(value, dict):
        return ""
    ts = value.get("add_date") or value.get("collect_date")
    if isinstance(ts, str) and ts.strip().lstrip("-").isdigit():
        ts = int(ts.strip())
    if not isinstance(ts, (int, float)) or ts <= 0:
        return ""
    try:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(ts, tz=timezone.utc).date().isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _extract(obj: Any, creds: list[dict], emails: set[str]) -> None:
    """Recursively pull credential records and loose emails from arbitrary JSON."""
    if isinstance(obj, dict):
        lower = {str(k).lower(): v for k, v in obj.items()}
        pw = next((str(lower[k]) for k in _PASSWORD_KEYS if lower.get(k)), "")
        password_type = "plain"
        if not pw:
            pw = next((str(lower[k]) for k in _HASH_KEYS if lower.get(k)), "")
            if pw:
                password_type = "hash"
        user = next((str(lower[k]) for k in _USER_KEYS if lower.get(k)), "")
        email = str(lower.get("email") or "")
        if not email and _EMAIL_RE.fullmatch(user):
            email = user
        if pw and (user or email):
            raw_source = lower.get("source")
            source = _source_name(raw_source) or _source_name(
                lower.get("database") or lower.get("breach")
            ) or "resecurity"
            date = _source_date(raw_source) or str(lower.get("date") or lower.get("leak_date") or "")
            creds.append({
                "username": user,
                "password": pw,
                "password_type": password_type,
                "email": email.lower() if email else "",
                "source": source,
                "date": date,
            })
        for v in obj.values():
            _extract(v, creds, emails)
    elif isinstance(obj, list):
        for v in obj:
            _extract(v, creds, emails)
    elif isinstance(obj, str):
        for m in _EMAIL_RE.findall(obj):
            emails.add(m.lower())


def _auth_header_value(scheme: str, key: str) -> str:
    """Basic means real HTTP Basic (base64 "key:"), not the literal word "Basic"
    glued onto the raw key — Resecurity's Breaches API confirmed-advertises
    `WWW-Authenticate: Basic realm="api"` and accepts the key as the username
    with an empty password."""
    if scheme.lower() == "basic":
        token = base64.b64encode(f"{key}:".encode()).decode()
        return f"Basic {token}"
    return f"{scheme} {key}".strip()


def search(target: str, limit: int = 100) -> dict[str, Any]:
    key = _api_key()
    base = _cfg("RESECURITY_API_BASE", "https://app.resecurity.com/api").rstrip("/")
    endpoint = _cfg("RESECURITY_ENDPOINT", "/breaches/index")
    qparam = _cfg("RESECURITY_QUERY_PARAM", "query")
    page_size_param = _cfg("RESECURITY_PAGE_SIZE_PARAM", "per-page")
    auth_header = _cfg("RESECURITY_AUTH_HEADER", "Authorization")
    scheme = _cfg_or_unset("RESECURITY_AUTH_SCHEME")
    if scheme is None:
        scheme = "Basic"
    limit = max(1, min(int(limit), 500))

    qs = urlencode({qparam: target, page_size_param: limit, "page": 1})
    url = f"{base}{endpoint}?{qs}"
    headers = {
        "User-Agent": "osprey-resecurity/1.0",
        "Accept": "application/json",
        auth_header: _auth_header_value(scheme, key),
    }
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=45) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        raise SystemExit(_diagnose_http_error(exc.code, detail, endpoint)) from exc
    except URLError as exc:
        raise SystemExit(
            f"ERROR: Resecurity network failure reaching {base!r}: {exc}. "
            "Check RESECURITY_API_BASE in .env."
        ) from exc

    try:
        data = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
        creds: list[dict] = []
        emails: set[str] = set()
        for m in _EMAIL_RE.findall(raw):
            emails.add(m.lower())
        return {"provider": "resecurity", "target": target,
                "credentials": creds, "emails": sorted(emails)[:limit],
                "warning": "non-JSON response parsed for emails only"}

    creds = []
    emails = set()
    _extract(data, creds, emails)
    # De-dup credentials on (username|email, password).
    seen: set[tuple] = set()
    uniq: list[dict] = []
    for c in creds:
        k = (c.get("email") or c.get("username"), c.get("password"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(c)
    return {"provider": "resecurity", "target": target,
            "credentials": uniq[:limit], "emails": sorted(emails)[:limit]}


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("Usage: _resecurity_cli.py search <target> [limit]", file=sys.stderr)
        raise SystemExit(2)
    action = argv[0].strip().lower()
    if action != "search":
        raise SystemExit(f"ERROR: unknown action {action!r} (use search)")
    if len(argv) < 2:
        raise SystemExit("ERROR: search requires a target")
    limit = int(argv[2]) if len(argv) > 2 else 100
    print(json.dumps(search(argv[1], limit), indent=2))


if __name__ == "__main__":
    main()
