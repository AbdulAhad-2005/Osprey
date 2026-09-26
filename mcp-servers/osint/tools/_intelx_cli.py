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
_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_MAX_COMBO_SEGMENT_LEN = 128


def _extract_url_combo(selector: str) -> dict[str, str] | None:
    """A credential-stuffing combo line commonly appears in IntelX's phonebook
    "urls" bucket as ``https://host/path:identity:password`` (sometimes
    ``...:first:last:password``) — confirmed via live QA testing against a
    real engagement target: genuine leaked credentials (a working login +
    plaintext password) surface this way with the CURRENT phonebook-only key,
    well before any Identity/leaks licence is involved. Naively treating every
    2+-colon URL as a combo is NOT safe though — also confirmed live:
    URL-encoded search-spam queries (non-Latin text, ad/gambling spam)
    routinely contain colons too and would
    otherwise be misparsed into fabricated fake "credentials", which is worse
    than dropping them (a false credential finding, not just a missed one).

    The one reliable discriminator found against real mixed data: genuine
    combo dumps are plain text — zero percent-encoding anywhere in the
    selector — while every spam/noise sample observed was heavily %XX-encoded.
    Combined with a sane segment-length cap, this had 100% precision/recall
    on a real 500-result sample (17/17 genuine combos kept, 5/5 spam entries
    correctly rejected). Returns None for an ordinary URL (no trailing combo).

    A rarer 4-segment shape (``url:first:last:password``) is only handled
    partially: the last segment before the password ("last") is kept as the
    identity and "first" ends up folded into the url string instead of lost
    outright — an acceptable simplification since there is no generic way to
    tell "first:last" apart from other 2-segment identity shapes (user:domain,
    etc.), and it never fabricates a password/identity that wasn't present.
    """
    if _PERCENT_ENCODED_RE.search(selector):
        return None
    parts = selector.split(":")
    # A genuine combo always has >= 4 parts here: the caller only calls this on
    # values already starting with "http(s)://", so the split is always
    # [scheme, "//host[/path]", identity, password, ...]. This also correctly
    # REJECTS a plain URL that merely has a port (e.g. "https://host:8443/x"
    # splits into exactly 3: [scheme, "//host", "8443/x"]) — an earlier version
    # of this fix used ">= 3" and misparsed that port number as a fake
    # "identity" with the path as a fake "password". The scheme-prefix check
    # is a second, cheap belt-and-suspenders guard against the same mistake.
    if len(parts) < 4 or not parts[1].startswith("//") or not parts[1][2:]:
        return None
    password = parts[-1].strip()
    identity = parts[-2].strip()
    url = ":".join(parts[:-2]).strip()
    if not password or not identity or not url:
        return None
    if len(password) > _MAX_COMBO_SEGMENT_LEN or len(identity) > _MAX_COMBO_SEGMENT_LEN:
        return None
    email = identity if _EMAIL_RE.match(identity) else ""
    return {"url": url, "username": "" if email else identity, "email": email, "password": password}


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
                "emails": [], "domains": [], "urls": [], "credentials": [],
                "warning": "no search id returned (invalid term or quota)"}
    selectors = _poll(_SEARCH_BASE, "/phonebook/search/result", search_id, key,
                      limit=maxresults, results_field="selectors")
    emails: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    credentials: list[dict[str, str]] = []
    seen: set[str] = set()
    for sel in selectors:
        val = str(sel.get("selectorvalue") or "").strip()
        if not val or val.lower() in seen:
            continue
        seen.add(val.lower())
        if _EMAIL_RE.match(val):
            emails.append(val.lower())
        elif val.lower().startswith(("http://", "https://")):
            # A URL-shaped selector may actually be a credential-stuffing
            # combo line the leak dump stored as "url:identity:password" —
            # check that BEFORE filing it as a plain url, or a real leaked
            # credential silently vanishes into a field nothing reads (see
            # _extract_url_combo; this is the exact gap live QA testing found).
            combo = _extract_url_combo(val)
            if combo:
                credentials.append(combo)
            else:
                urls.append(val)
        elif "." in val and " " not in val:
            domains.append(val.lower())
    return {"provider": "intelx", "mode": "phonebook", "term": term,
            "emails": emails, "domains": domains, "urls": urls,
            "credentials": credentials, "selector_count": len(selectors)}


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
