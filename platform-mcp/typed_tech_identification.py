"""Register typed FastMCP tools for the technology-identification (WEBAPP) tools.

Same pattern as typed_recon_network.py: each tool calls the same backend
execute API as platform_exec, with explicit Python parameters so the LLM
does not have to reverse-engineer params_json for these four tools.
"""

from __future__ import annotations

from typing import Any, Callable


def register_typed_tech_identification_tools(
    mcp: Any,
    *,
    execute: Callable[..., str],
) -> int:
    """
    Register whatweb_scan, wappalyzer_scan, tech_stack_analyze, wafw00f_scan as typed tools.

    ``execute(tool_name, params, additional_args, timeout_seconds) -> str``
    must bind engagement and POST /api/v1/mcp/execute (same as platform_exec).
    """

    def whatweb_scan(
        target: str,
        aggression: str = "1",
        verbose: bool = False,
        additional_args: str = "",
        timeout_seconds: int = 300,
    ) -> str:
        """Technology fingerprinting via WhatWeb (target=). aggression 1=passive (default) to 4=aggressive."""
        params: dict[str, Any] = {"target": target}
        if aggression and str(aggression) != "1":
            params["aggression"] = aggression
        if verbose:
            params["verbose"] = True
        return execute(
            "whatweb_scan",
            params,
            additional_args=additional_args,
            timeout_seconds=timeout_seconds,
        )

    def wappalyzer_scan(
        target: str,
        additional_args: str = "",
        timeout_seconds: int = 300,
    ) -> str:
        """Categorized technology detection via Wappalyzer Python library (target=)."""
        return execute(
            "wappalyzer_scan",
            {"target": target},
            additional_args=additional_args,
            timeout_seconds=timeout_seconds,
        )

    def tech_stack_analyze(
        target: str,
        aggression: str = "1",
        verbose: bool = False,
        additional_args: str = "",
        timeout_seconds: int = 300,
    ) -> str:
        """All-in-one: WhatWeb + Wappalyzer + HTTP headers + security-concern assessment (target=). Slower — use for a comprehensive report."""
        params: dict[str, Any] = {"target": target}
        if aggression and str(aggression) != "1":
            params["aggression"] = aggression
        if verbose:
            params["verbose"] = True
        return execute(
            "tech_stack_analyze",
            params,
            additional_args=additional_args,
            timeout_seconds=timeout_seconds,
        )

    def wafw00f_scan(
        target: str,
        additional_args: str = "",
        timeout_seconds: int = 120,
    ) -> str:
        """WAF/CDN product fingerprinting via wafw00f (target=). Names the actual WAF product, unlike generic CDN hints."""
        return execute(
            "wafw00f_scan",
            {"target": target},
            additional_args=additional_args,
            timeout_seconds=timeout_seconds,
        )

    mcp.tool(name="whatweb_scan")(whatweb_scan)
    mcp.tool(name="wappalyzer_scan")(wappalyzer_scan)
    mcp.tool(name="tech_stack_analyze")(tech_stack_analyze)
    mcp.tool(name="wafw00f_scan")(wafw00f_scan)
    return 4
