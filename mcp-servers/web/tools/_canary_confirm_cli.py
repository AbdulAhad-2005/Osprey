"""Deterministic reflected-payload confirmation — plans/harness/12-
deterministic-evidence-verification.md Step 2.

The caller has already injected a unique token (their choice — a random
string, a payload fragment, whatever they're testing) into a request they
control; this fetches the resulting URL and reports, deterministically,
whether that exact token comes back in the response — the "per-run nonce
reflected back" primitive "Forgeable Confirmation: Deterministic Rules vs AI
Judges" (arXiv 2609.24200) found far harder to forge than an AI judge's
verdict: the platform checks a byte-for-byte fact, not a claim about one.

Not an MCP tool — underscore-prefixed. Wrapped by canary_confirm.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _deterministic_confirm_lib import fetch  # noqa: E402

_CONTEXT_RADIUS = 60


def confirm(
    url: str,
    canary: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = 15.0,
) -> dict[str, Any]:
    if not canary.strip():
        return {"error": "canary is required — the exact token you injected"}
    result = fetch(url, method=method, headers=headers, body=body, timeout=timeout)
    if not result.get("ok"):
        return {"canary": canary, "url": url, "found": False, "error": result.get("error")}

    haystack = (result.get("body") or "") + " ".join(
        f"{k}: {v}" for k, v in (result.get("headers") or {}).items()
    )
    idx = haystack.find(canary)
    found = idx != -1
    context = ""
    if found:
        start = max(0, idx - _CONTEXT_RADIUS)
        end = min(len(haystack), idx + len(canary) + _CONTEXT_RADIUS)
        context = haystack[start:end]
    return {
        "canary": canary,
        "url": url,
        "status_code": result.get("status_code"),
        "found": found,
        "occurrences": haystack.count(canary) if found else 0,
        "context": context,
    }


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print(
            "Usage: _canary_confirm_cli.py <url> <canary> [method] [headers_json] [body] [timeout]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    url, canary = argv[0], argv[1]
    method = argv[2] if len(argv) > 2 else "GET"
    headers_json = argv[3] if len(argv) > 3 else ""
    body = argv[4] if len(argv) > 4 else ""
    timeout = float(argv[5]) if len(argv) > 5 and argv[5] else 15.0
    headers = json.loads(headers_json) if headers_json.strip() else None
    print(json.dumps(confirm(url, canary, method=method, headers=headers, body=body, timeout=timeout), indent=2))


if __name__ == "__main__":
    main()
