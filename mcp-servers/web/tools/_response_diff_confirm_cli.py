"""Deterministic response-differential confirmation — plans/harness/12-
deterministic-evidence-verification.md Step 2.

Fetches two requests (e.g. a boolean-TRUE vs boolean-FALSE blind-SQLi
payload, or an authenticated vs unauthenticated request) and reports a
structural diff — status code, length delta, and a real content diff —
instead of an agent's own impression that "the response looked different".
The deterministic confirmation a blind-injection or authorization-bypass
claim needs.

Not an MCP tool — underscore-prefixed. Wrapped by response_diff_confirm.py.
"""

from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _deterministic_confirm_lib import fetch  # noqa: E402

_MAX_DIFF_LINES = 40


def _diff_lines(body_a: str, body_b: str) -> list[str]:
    # Line-based diff over a bounded slice — a byte diff on minified/JS-heavy
    # bodies is noise; splitlines() on the first ~4000 chars each keeps this
    # readable and cheap regardless of how large the real bodies are.
    a_lines = body_a[:4000].splitlines()
    b_lines = body_b[:4000].splitlines()
    diff = list(difflib.unified_diff(a_lines, b_lines, lineterm="", n=1))
    return diff[:_MAX_DIFF_LINES]


def confirm(
    url_a: str,
    url_b: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body_a: str = "",
    body_b: str = "",
    timeout: float = 15.0,
) -> dict[str, Any]:
    result_a = fetch(url_a, method=method, headers=headers, body=body_a, timeout=timeout)
    result_b = fetch(url_b, method=method, headers=headers, body=body_b, timeout=timeout)
    if not result_a.get("ok") or not result_b.get("ok"):
        return {
            "url_a": url_a, "url_b": url_b, "identical": None,
            "error_a": result_a.get("error"), "error_b": result_b.get("error"),
        }

    status_a, status_b = result_a["status_code"], result_b["status_code"]
    len_a, len_b = result_a["body_length"], result_b["body_length"]
    body_diff = _diff_lines(result_a.get("body") or "", result_b.get("body") or "")
    identical = status_a == status_b and (result_a.get("body") or "") == (result_b.get("body") or "")
    return {
        "url_a": url_a, "url_b": url_b,
        "status_code_a": status_a, "status_code_b": status_b,
        "body_length_a": len_a, "body_length_b": len_b,
        "length_delta": len_b - len_a,
        "identical": identical,
        "diff": body_diff,
    }


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print(
            "Usage: _response_diff_confirm_cli.py <url_a> <url_b> [method] [headers_json] "
            "[body_a] [body_b] [timeout]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    url_a, url_b = argv[0], argv[1]
    method = argv[2] if len(argv) > 2 else "GET"
    headers_json = argv[3] if len(argv) > 3 else ""
    body_a = argv[4] if len(argv) > 4 else ""
    body_b = argv[5] if len(argv) > 5 else ""
    timeout = float(argv[6]) if len(argv) > 6 and argv[6] else 15.0
    headers = json.loads(headers_json) if headers_json.strip() else None
    print(json.dumps(
        confirm(url_a, url_b, method=method, headers=headers, body_a=body_a, body_b=body_b, timeout=timeout),
        indent=2,
    ))


if __name__ == "__main__":
    main()
