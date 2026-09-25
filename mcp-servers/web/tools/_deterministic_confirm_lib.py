"""Shared HTTP fetch for canary_confirm/response_diff_confirm — the
deterministic-verification primitives from plans/harness/12-deterministic-
evidence-verification.md Step 2. Stdlib-only (urllib), matching
_proxy_replay_cli.py's own dependency-free style — no extra pip install
needed inside Kali for something this simple.
"""

from __future__ import annotations

from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_MAX_BODY_CHARS = 40_000


def fetch(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = 15.0,
) -> dict[str, Any]:
    """One HTTP call, always returning a result dict (never raises) — a
    network failure is itself a fact worth reporting, not something that
    should crash the confirmation attempt."""
    method = (method or "GET").upper()
    data = body.encode("utf-8") if body and method not in ("GET", "HEAD") else None
    req = Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return {
                "ok": True,
                "url": url,
                "status_code": resp.status,
                "headers": dict(resp.headers),
                "body": raw[:_MAX_BODY_CHARS],
                "body_length": len(raw),
            }
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return {
            "ok": True,
            "url": url,
            "status_code": exc.code,
            "headers": dict(exc.headers or {}),
            "body": raw[:_MAX_BODY_CHARS],
            "body_length": len(raw),
        }
    except URLError as exc:
        return {"ok": False, "url": url, "error": f"network failure: {exc}"}
