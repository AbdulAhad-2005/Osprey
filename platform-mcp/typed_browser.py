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
        additional_args: str = "",
        timeout_seconds: int = 240,
        engagement_id: str = "",
    ) -> str:
        """Render a JS/SPA page in real Chromium and extract what static crawlers miss:
        client-side routes (SPA links), XHR/fetch API endpoints the app calls at runtime,
        forms + inputs (injection-point candidates), cookie security flags, mixed content,
        and a full-page screenshot. Use on any React/Vue/Angular/Next app before deeper
        testing. wait_until=networkidle waits for XHR to settle.
        engagement_id= pins the call to a specific engagement."""
        params: dict[str, Any] = {"url": url, "wait_until": wait_until}
        if not screenshot:
            params["screenshot"] = "false"
        return execute("browser_scrape", params, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def browser_flow(
        steps: str,
        url: str = "",
        additional_args: str = "",
        timeout_seconds: int = 300,
        engagement_id: str = "",
    ) -> str:
        """Drive a real browser through a declarative flow in ONE session — for login,
        authenticated navigation, and BUSINESS LOGIC testing. steps= a JSON list of step
        objects; supported actions: goto{url}, fill{selector,value}, click{selector},
        press{selector?,key}, wait{ms|selector}, select{selector,value},
        extract{selector,name}, assert_text{text}, screenshot{name?}, set_header{name,value},
        set_cookie{name,value}. Returns the per-step trace, captured API calls, extracted
        values, assertion results and final cookies. Example: log in, then assert an admin-only
        string is present as a low-priv user (auth bypass). engagement_id= pins the engagement."""
        params: dict[str, Any] = {"steps": steps}
        if url.strip():
            params["url"] = url.strip()
        return execute("browser_flow", params, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    for fn in (browser_scrape, browser_flow):
        mcp.tool(name=fn.__name__)(fn)
    return 2
