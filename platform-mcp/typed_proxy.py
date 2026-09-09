"""Typed FastMCP tools for full-session passive traffic capture (mitmproxy).

Start once per engagement with proxy_start, route browser_flow/browser_scrape
(their own proxy_port= param) or platform_shell curl/sqlmap through the
returned port, then query/replay from the capture with the tools below —
see skills/web/traffic-capture.md for the full workflow.
"""

from __future__ import annotations

from typing import Any, Callable


def register_typed_proxy_tools(mcp: Any, *, execute: Callable[..., str]) -> int:
    def proxy_start(
        engagement_id: str,
        timeout_seconds: int = 20,
    ) -> str:
        """Start full-session passive traffic capture (mitmdump) for this engagement.
        Idempotent — calling again returns the existing running instance instead of
        starting a duplicate. Point browser_flow/browser_scrape's proxy_port= at the
        returned port, or route platform_shell curl/sqlmap through it with
        -x http://127.0.0.1:<port> -k. Captures EVERYTHING sent through it across as
        many separate calls as you make, unlike browser_flow's own captured_requests
        (scoped to one step sequence). engagement_id is required — it scopes the
        port/log/pidfile so concurrent engagements on the same container don't collide."""
        return execute("proxy_start", {"engagement_id": engagement_id},
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def proxy_stop(
        engagement_id: str,
        timeout_seconds: int = 15,
    ) -> str:
        """Stop full-session traffic capture for this engagement and free its port.
        Run at engagement end — a leaked mitmdump holds its port indefinitely and the
        next engagement sharing the container gets a confusing "already running"
        status for a capture that isn't theirs."""
        return execute("proxy_stop", {"engagement_id": engagement_id},
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def proxy_flows(
        engagement_id: str,
        host: str = "",
        method: str = "",
        contains: str = "",
        min_status: int = 0,
        limit: int = 100,
        timeout_seconds: int = 30,
    ) -> str:
        """List/filter traffic captured by proxy_start. host= substring filter on request
        host, method= exact HTTP method filter, contains= substring filter on the full
        URL, min_status= only rows with status_code >= this. Compact rows (method, url,
        status, timing) — use proxy_flow_detail for full headers+body on one flow_id."""
        params: dict[str, Any] = {"engagement_id": engagement_id}
        if host.strip():
            params["host"] = host.strip()
        if method.strip():
            params["method"] = method.strip()
        if contains.strip():
            params["contains"] = contains.strip()
        if min_status:
            params["min_status"] = min_status
        if limit:
            params["limit"] = limit
        return execute("proxy_flows", params, timeout_seconds=timeout_seconds,
                       engagement_id=engagement_id)

    def proxy_flow_detail(
        engagement_id: str,
        flow_id: int,
        timeout_seconds: int = 20,
    ) -> str:
        """Full detail (both directions' headers + body) for one flow_id from proxy_flows."""
        return execute("proxy_flow_detail", {"engagement_id": engagement_id, "flow_id": flow_id},
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def proxy_replay(
        engagement_id: str,
        flow_id: int,
        method_override: str = "",
        url_override: str = "",
        headers_json: str = "",
        body_override: str = "",
        timeout_seconds: int = 45,
    ) -> str:
        """Re-send a captured flow (from proxy_flows), optionally tampered — the repeater
        half of the capture workflow for IDOR/auth-bypass/param-pollution testing. Works
        standalone against any captured flow, browser session long closed or not (unlike
        browser_flow's own session-bound replay step, which needs a live Playwright
        session's cookies). headers_json= JSON object of headers to override/add on top
        of the original captured ones; leave method/url/body overrides empty to replay
        unmodified as a baseline before tampering."""
        params: dict[str, Any] = {"engagement_id": engagement_id, "flow_id": flow_id}
        if method_override.strip():
            params["method_override"] = method_override.strip()
        if url_override.strip():
            params["url_override"] = url_override.strip()
        if headers_json.strip():
            params["headers_json"] = headers_json.strip()
        if body_override:
            params["body_override"] = body_override
        return execute("proxy_replay", params, timeout_seconds=timeout_seconds,
                       engagement_id=engagement_id)

    tools = (proxy_start, proxy_stop, proxy_flows, proxy_flow_detail, proxy_replay)
    for fn in tools:
        mcp.tool(name=fn.__name__)(fn)
    return len(tools)
