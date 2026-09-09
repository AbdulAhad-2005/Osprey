"""Re-send a captured flow, with optional tampering — a standalone repeater.

Not an MCP tool — underscore-prefixed. Wrapped by proxy_replay.py.

Complements browser_flow's own `replay` step (which needs a live Playwright
session and its cookies): this one works against ANY previously captured
flow, browser session long closed or not, by rebuilding the request from
what proxy_capture_addon.py logged — the actual "repeater" half of a
Caido/Burp-style workflow.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _proxy_flows_lib import get_flow  # noqa: E402

# Headers that only made sense on the original connection — replaying them
# verbatim breaks the new request (stale length, wrong encoding negotiation,
# a proxy-only Connection value) rather than testing anything.
_STRIP_HEADERS = {"content-length", "host", "connection", "accept-encoding"}


def replay(
    engagement_id: str,
    flow_id: int,
    method_override: str = "",
    url_override: str = "",
    headers_override: dict[str, str] | None = None,
    body_override: str = "",
) -> dict[str, Any]:
    flow = get_flow(engagement_id, flow_id)
    if flow is None:
        return {"error": f"flow_id {flow_id} not found for engagement {engagement_id}"}

    method = (method_override or flow.get("method") or "GET").upper()
    url = url_override or flow.get("url") or ""
    if not url:
        return {"error": "captured flow has no URL to replay"}

    headers = {k: v for k, v in (flow.get("request_headers") or {}).items() if k.lower() not in _STRIP_HEADERS}
    if headers_override:
        headers.update(headers_override)

    body = body_override if body_override else flow.get("request_body", "")
    data = body.encode("utf-8") if body and method not in ("GET", "HEAD") else None

    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            return {
                "flow_id": flow_id,
                "replayed_method": method,
                "replayed_url": url,
                "status_code": resp.status,
                "response_headers": dict(resp.headers),
                "response_body": resp_body[:8000],
            }
    except HTTPError as exc:
        resp_body = exc.read().decode("utf-8", errors="replace")
        return {
            "flow_id": flow_id,
            "replayed_method": method,
            "replayed_url": url,
            "status_code": exc.code,
            "response_headers": dict(exc.headers or {}),
            "response_body": resp_body[:8000],
        }
    except URLError as exc:
        return {"error": f"replay network failure: {exc}"}


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print(
            "Usage: _proxy_replay_cli.py <engagement_id> <flow_id> "
            "[method_override] [url_override] [headers_json] [body_override]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    engagement_id, flow_id = argv[0], int(argv[1])
    method_override = argv[2] if len(argv) > 2 else ""
    url_override = argv[3] if len(argv) > 3 else ""
    headers_json = argv[4] if len(argv) > 4 else ""
    body_override = argv[5] if len(argv) > 5 else ""
    headers_override = json.loads(headers_json) if headers_json.strip() else None
    print(json.dumps(replay(engagement_id, flow_id, method_override, url_override, headers_override, body_override), indent=2))


if __name__ == "__main__":
    main()
