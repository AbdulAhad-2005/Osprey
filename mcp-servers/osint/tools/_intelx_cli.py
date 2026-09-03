"""Shared Intelligence X (intelx.io) REST helpers (not an MCP tool — underscore-prefixed).

Two IntelX products, two API instances (see https://github.com/IntelligenceX/SDK):

  * Search / Phonebook API  — base https://2.intelx.io, key = INTELX_API_KEY.
    Phonebook search turns a domain into the emails / subdomains / URLs that appear
    across IntelX's indexed leaks and pastes. Great passive email harvest.

  * Identity / Leaks API    — base https://3.intelx.io, key = INTELX_IDENTITY_API_KEY.
    `/live/search/internal` returns actual leaked account records (user + password)
    for a selector. Requires an Identity Portal licence; skipped when no key is set.

Auth is the `X-Key` header. Searches are async: POST starts a search and returns an
id; GET polls the result until status != 3 (0=results, 1=done, 2=id-not-found,
3=keep-waiting). Prints a single JSON object to stdout; the backend `parse_intelx`
turns it into typed CREDENTIAL / EMAIL / SUBDOMAIN findings.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

_SEARCH_BASE = (os.environ.get("INTELX_API_BASE") or "https://2.intelx.io").rstrip("/")
_IDENTITY_BASE = (os.environ.get("INTELX_IDENTITY_BASE") or "https://3.intelx.io").rstrip("/")
_UA = "osprey-intelx/1.0"

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}$")
# A raw combo line "identity:secret" (email/user : password) as leak dumps store it.
_COMBO_RE = re.compile(r"^\s*([^\s:;|,]+)\s*[:;|,]\s*(\S.*?)\s*$")


def _search_key() -> str:
    key = (os.environ.get("INTELX_API_KEY") or "").strip()
    if not key:
        raise SystemExit(
            "ERROR: INTELX_API_KEY is not set. Add it to .env (see intelx.io/account?tab=developer) "
            "and restart kali-tools/backend."
        )
    return key


def _request(url: str, key: str, *, body: dict | None = None, timeout: int = 30) -> Any:
    headers = {"X-Key": key, "User-Agent": _UA, "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw.strip() else {}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        raise SystemExit(f"ERROR: IntelX HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise SystemExit(f"ERROR: IntelX network failure: {exc}") from exc


def _poll(base: str, result_path: str, search_id: str, key: str, *, limit: int, results_field: str) -> list[dict]:
    """Poll a result endpoint until the search finishes; accumulate records."""
    out: list[dict] = []
    for _ in range(20):  # ~ up to 20 * 2s = 40s of polling
        qs = urlencode({"id": search_id, "limit": limit, "offset": -1})
        data = _request(f"{base}{result_path}?{qs}", key)
        rows = data.get(results_field) or []
        if isinstance(rows, list):
            out.extend(r for r in rows if isinstance(r, dict))
        status = data.get("status")
        if status in (0, 1, 2):  # 0=have results, 1=no more, 2=id not found
            break
        if len(out) >= limit:
            break
        time.sleep(2)
    return out[:limit]


def phonebook(term: str, maxresults: int = 200) -> dict[str, Any]:
    """Domain/selector → emails, subdomains, URLs harvested from IntelX's index."""
    key = _search_key()
    maxresults = max(1, min(int(maxresults), 1000))
    start = _request(
        f"{_SEARCH_BASE}/phonebook/search",
        key,
        body={
            "term": term,
            "maxresults": maxresults,
            "media": 0,
            "target": 0,  # 0 = all selector types; we classify client-side
            "timeout": 10,
            "terminate": [],
            "buckets": [],
            "lookuplevel": 0,
            "sort": 2,
            "datefrom": "",
            "dateto": "",
        },
    )
    search_id = start.get("id")
    if not search_id:
        return {"provider": "intelx", "mode": "phonebook", "term": term,
                "emails": [], "domains": [], "urls": [],
                "warning": "no search id returned (invalid term or quota)"}
    selectors = _poll(_SEARCH_BASE, "/phonebook/search/result", search_id, key,
                      limit=maxresults, results_field="selectors")
    emails: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    seen: set[str] = set()
    for sel in selectors:
        val = str(sel.get("selectorvalue") or "").strip()
        if not val or val.lower() in seen:
            continue
        seen.add(val.lower())
        if _EMAIL_RE.match(val):
            emails.append(val.lower())
        elif val.lower().startswith(("http://", "https://")):
            urls.append(val)
        elif "." in val and " " not in val:
            domains.append(val.lower())
    return {"provider": "intelx", "mode": "phonebook", "term": term,
            "emails": emails, "domains": domains, "urls": urls,
            "selector_count": len(selectors)}


def leaks(selector: str, maxresults: int = 100) -> dict[str, Any]:
    """Selector → leaked account records (user + password) via the Identity API.

    Requires INTELX_IDENTITY_API_KEY. Returns credentials with the raw values
    intact (offensive use) — never masked.
    """
    key = (os.environ.get("INTELX_IDENTITY_API_KEY") or "").strip()
    if not key:
        return {"provider": "intelx", "mode": "leaks", "term": selector,
                "credentials": [],
                "warning": "INTELX_IDENTITY_API_KEY not set — leaked-credential lookup skipped"}
    maxresults = max(1, min(int(maxresults), 1000))
    start = _request(
        f"{_IDENTITY_BASE}/live/search/internal",
        key,
        body={
            "selector": selector,
            "bucket": "",
            "limit": maxresults,
            "datefrom": "",
            "dateto": "",
            "terminate": [],
            "skipinvalid": False,
            "analyze": False,
        },
    )
    records: list[dict]
    if isinstance(start.get("records"), list):
        records = [r for r in start["records"] if isinstance(r, dict)]
    else:
        search_id = start.get("id")
        records = (
            _poll(_IDENTITY_BASE, "/live/search/result", search_id, key,
                  limit=maxresults, results_field="records")
            if search_id else []
        )
    creds = [_normalize_leak_record(r) for r in records]
    creds = [c for c in creds if c.get("username") or c.get("email")]
    return {"provider": "intelx", "mode": "leaks", "term": selector, "credentials": creds[:maxresults]}


def _normalize_leak_record(rec: dict) -> dict[str, Any]:
    """Map an IntelX Identity record to our credential shape, defensively.

    Field names vary between buckets, so fall back to parsing the raw `line`
    ("identity:secret") when explicit user/password fields are absent.
    """
    user = str(rec.get("user") or rec.get("username") or "").strip()
    password = str(rec.get("password") or rec.get("pass") or "").strip()
    email = str(rec.get("email") or "").strip()
    if (not user and not email) or not password:
        line = str(rec.get("line") or rec.get("data") or "").strip()
        m = _COMBO_RE.match(line)
        if m:
            ident, secret = m.group(1), m.group(2)
            if _EMAIL_RE.match(ident) and not email:
                email = ident
            elif not user:
                user = ident
            if not password:
                password = secret
    if not email and _EMAIL_RE.match(user):
        email = user
    return {
        "username": user,
        "password": password,
        "email": email.lower() if email else "",
        "password_type": str(rec.get("passwordtype") or rec.get("password_type") or "plain"),
        "source": str(rec.get("sourceshort") or rec.get("sourcename") or rec.get("bucket") or "intelx"),
        "date": str(rec.get("date") or ""),
    }


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "Usage: _intelx_cli.py phonebook <domain> [maxresults]\n"
            "       _intelx_cli.py leaks <selector> [maxresults]\n"
            "       _intelx_cli.py all <domain> [maxresults]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    action = argv[0].strip().lower()
    term = argv[1] if len(argv) > 1 else ""
    if not term:
        raise SystemExit(f"ERROR: {action} requires a domain/selector")
    n = int(argv[2]) if len(argv) > 2 else 200

    if action == "phonebook":
        print(json.dumps(phonebook(term, n), indent=2))
    elif action == "leaks":
        print(json.dumps(leaks(term, n), indent=2))
    elif action == "all":
        pb = phonebook(term, n)
        lk = leaks(term, min(n, 100))
        print(json.dumps({"provider": "intelx", "mode": "all", "term": term,
                          "phonebook": pb, "leaks": lk}, indent=2))
    else:
        raise SystemExit(f"ERROR: unknown action {action!r} (use phonebook|leaks|all)")


if __name__ == "__main__":
    main()
