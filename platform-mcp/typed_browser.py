"""Typed FastMCP tools for the headless-browser layer (Playwright).

browser_scrape renders a JS/SPA page and extracts the runtime attack surface
(client-side routes, XHR/fetch APIs, forms, cookie flags, screenshot).
browser_flow drives a declarative step sequence in one session for login,
authenticated navigation, and business-logic testing.
"""

from __future__ import annotations

from typing import Any, Callable


def register_typed_browser_tools(mcp: Any, *, execute: Callable[..., str]) -> int:
    def browser_scrape(
        url: str,
        wait_until: str = "networkidle",
        screenshot: bool = True,
        proxy_port: int = 0,
        additional_args: str = "",
        timeout_seconds: int = 240,
        engagement_id: str = "",
    ) -> str:
        """Render a JS/SPA page in real Chromium and extract what static crawlers miss:
        client-side routes (SPA links), XHR/fetch API endpoints the app calls at runtime,
        forms + inputs (injection-point candidates), cookie security flags, mixed content,
        and a full-page screenshot. Use on any React/Vue/Angular/Next app before deeper
        testing. wait_until=networkidle waits for XHR to settle. proxy_port= routes this
        session through a proxy_start capture instance (its returned port) for full passive
        traffic capture beyond this call's own XHR list — see proxy_flows/proxy_replay.
        engagement_id= pins the call to a specific engagement."""
        params: dict[str, Any] = {"url": url, "wait_until": wait_until}
        if not screenshot:
            params["screenshot"] = "false"
        if proxy_port:
            params["proxy_port"] = proxy_port
        return execute("browser_scrape", params, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def browser_flow(
        steps: str,
        url: str = "",
        proxy_port: int = 0,
        additional_args: str = "",
        timeout_seconds: int = 300,
        engagement_id: str = "",
    ) -> str:
        """Drive a real browser through a declarative flow in ONE authenticated session — for
        login, authenticated navigation, BUSINESS LOGIC testing, and a session-aware HTTP
        repeater. steps= a JSON list of step objects; supported actions: goto{url},
        fill{selector,value}, click{selector}, press{selector?,key}, wait{ms|selector},
        select{selector,value}, upload{selector,files} (file-upload testing),
        extract{selector,name}, assert_text{text}, screenshot{name?}, set_header{name,value},
        set_cookie{name,value},
        snapshot{name?,limit?} (compact map of the live DOM's interactive elements with CSS
        selectors — SEE the page mid-flow then act; iterate open->snapshot->act like a human),
        replay{url,method?,headers?,body?,json?,name?} (re-send an HTTP request THROUGH the live
        logged-in session, cookies intact — tamper any field to test IDOR / auth-bypass / param
        pollution, then read the full status+headers+body back).
        Returns the per-step trace, captured API calls (with headers+body, replayable),
        snapshots, replays, extracted values, assertions and final cookies. Example: log in,
        capture GET /api/orders/123, replay it as /api/orders/124, check for 2xx (IDOR).
        proxy_port= routes this whole session through a proxy_start capture instance for a
        full passive history beyond this one flow (see proxy_flows/proxy_replay) — use when
        you want to browse organically across several separate calls, not just this one
        declared step sequence.
        engagement_id= pins the engagement."""
        params: dict[str, Any] = {"steps": steps}
        if url.strip():
            params["url"] = url.strip()
        if proxy_port:
            params["proxy_port"] = proxy_port
        return execute("browser_flow", params, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    for fn in (browser_scrape, browser_flow):
        mcp.tool(name=fn.__name__)(fn)
    return 2
