"""Typed FastMCP tool for free general web search (no API key).

A distinct parameter shape (query/limit) from typed_osint.py's generic
domain/url/target/email/... factory, so it gets its own small file rather
than being forced into that one.
"""

from __future__ import annotations

from typing import Any, Callable


def register_typed_web_search_tools(mcp: Any, *, execute: Callable[..., str]) -> int:
    def web_search(
        query: str,
        limit: int = 10,
        engagement_id: str = "",
        timeout_seconds: int = 45,
    ) -> str:
        """Free general web search (DuckDuckGo, no API key, no cost). Use for anything
        the internal catalog can't answer from a target directly: fresh CVE PoC/writeup
        hunting once a version is fingerprinted (searchsploit's offline Exploit-DB lags
        real disclosures and misses most GitHub-only PoCs — try this when it comes up
        empty), current technique research, product/vendor advisories. Read-only, no
        target contact — not gated. engagement_id= pins the call to a specific engagement."""
        params: dict[str, Any] = {"query": query}
        if limit:
            params["limit"] = limit
        return execute("web_search", params, timeout_seconds=timeout_seconds,
                       engagement_id=engagement_id)

    mcp.tool(name=web_search.__name__)(web_search)
    return 1
