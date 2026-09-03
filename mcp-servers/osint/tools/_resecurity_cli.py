"""Shared Resecurity credential-intel REST helper (not an MCP tool — underscore-prefixed).

Resecurity does not publish an open API contract, so this client is intentionally
*configurable* — point it at your account's endpoint via env and it adapts:

    RESECURITY_API_KEY      (required)  your API key/token
    RESECURITY_API_BASE     default https://api.resecurity.com
    RESECURITY_ENDPOINT     default /v1/leaks/search   (path to hit)
    RESECURITY_QUERY_PARAM  default query              (query-string param name)
    RESECURITY_AUTH_HEADER  default Authorization      (header carrying the key)
    RESECURITY_AUTH_SCHEME  default Bearer             ("" for a bare key header)

It performs a GET, then defensively walks whatever JSON comes back for
credential-shaped records (email / username + password) and loose emails, so the
backend `parse_resecurity` gets typed CREDENTIAL / EMAIL findings regardless of the
exact response shape. Leaked creds are stored intact (offensive) and graded as
INFERRED breach leads.
"""

from __future__ import annotations

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
_USER_KEYS = ("username", "user", "login", "account")


def _cfg(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _api_key() -> str:
    key = _cfg("RESECURITY_API_KEY")
    if not key:
        raise SystemExit(
            "ERROR: RESECURITY_API_KEY is not set. Add it (and optionally "
            "RESECURITY_API_BASE / RESECURITY_ENDPOINT for your account) to .env "
            "and restart kali-tools/backend."
        )
    return key


def _extract(obj: Any, creds: list[dict], emails: set[str]) -> None:
    """Recursively pull credential records and loose emails from arbitrary JSON."""
    if isinstance(obj, dict):
        lower = {str(k).lower(): v for k, v in obj.items()}
        pw = next((str(lower[k]) for k in _PASSWORD_KEYS if lower.get(k)), "")
        user = next((str(lower[k]) for k in _USER_KEYS if lower.get(k)), "")
        email = str(lower.get("email") or "")
        if not email and _EMAIL_RE.fullmatch(user):
            email = user
        if pw and (user or email):
            creds.append({
                "username": user,
                "password": pw,
                "email": email.lower() if email else "",
                "source": str(lower.get("source") or lower.get("database") or lower.get("breach") or "resecurity"),
                "date": str(lower.get("date") or lower.get("leak_date") or ""),
            })
        for v in obj.values():
            _extract(v, creds, emails)
    elif isinstance(obj, list):
        for v in obj:
            _extract(v, creds, emails)
    elif isinstance(obj, str):
        for m in _EMAIL_RE.findall(obj):
            emails.add(m.lower())


def search(target: str, limit: int = 100) -> dict[str, Any]:
    key = _api_key()
    base = _cfg("RESECURITY_API_BASE", "https://api.resecurity.com").rstrip("/")
    endpoint = _cfg("RESECURITY_ENDPOINT", "/v1/leaks/search")
    qparam = _cfg("RESECURITY_QUERY_PARAM", "query")
    auth_header = _cfg("RESECURITY_AUTH_HEADER", "Authorization")
    scheme = _cfg("RESECURITY_AUTH_SCHEME", "Bearer")
    limit = max(1, min(int(limit), 500))

    qs = urlencode({qparam: target, "limit": limit})
    url = f"{base}{endpoint}?{qs}"
    headers = {
        "User-Agent": "osprey-resecurity/1.0",
        "Accept": "application/json",
        auth_header: f"{scheme} {key}".strip(),
    }
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=45) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        raise SystemExit(f"ERROR: Resecurity HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise SystemExit(f"ERROR: Resecurity network failure: {exc}") from exc

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
