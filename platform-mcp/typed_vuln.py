"""Typed FastMCP tools for the vulnerability-analysis phase.

Same backend execute path as platform_exec, with explicit parameters so the
Commander does not hand-build params_json. These are ACTIVE/GATED scanners —
run them on the attack surface recon mapped (live hosts, detected tech,
injection-point candidates), not blindly across every asset.
"""

from __future__ import annotations

from typing import Any, Callable


def register_typed_vuln_tools(mcp: Any, *, execute: Callable[..., str]) -> int:
    def nuclei_scan(
        target: str,
        severity: str = "",
        tags: str = "",
        template: str = "",
        additional_args: str = "",
        timeout_seconds: int = 600,
        engagement_id: str = "",
    ) -> str:
        """Template-based vuln scanning via nuclei (target= URL/host). Filter with
        severity=critical,high,medium and/or tags=cve,rce,lfi,sqli,xss; template= a
        custom template path. Emits JSONL parsed into CVE/severity findings. The
        recon→vuln workhorse — run on live hosts once tech is known.
        engagement_id= pins the call to a specific engagement."""
        params: dict[str, Any] = {"target": target}
        if severity.strip():
            params["severity"] = severity.strip()
        if tags.strip():
            params["tags"] = tags.strip()
        if template.strip():
            params["template"] = template.strip()
        return execute("nuclei_scan", params, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def nikto_scan(
        target: str,
        additional_args: str = "",
        timeout_seconds: int = 600,
        engagement_id: str = "",
    ) -> str:
        """Web-server misconfiguration / dated-software scan via nikto (target= URL/host).
        Finds dangerous files, default pages, missing headers, exposed backups.
        engagement_id= pins the call to a specific engagement."""
        return execute("nikto_scan", {"target": target}, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def wpscan_analyze(
        url: str,
        additional_args: str = "",
        timeout_seconds: int = 600,
        engagement_id: str = "",
    ) -> str:
        """WordPress vuln scan via wpscan (url=). Enumerates core/plugin/theme versions
        and their known CVEs. Use when tech fingerprinting flags WordPress. Add an API
        token via additional_args (--api-token …) for full vuln data.
        engagement_id= pins the call to a specific engagement."""
        return execute("wpscan_analyze", {"url": url}, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def sqlmap_scan(
        url: str,
        data: str = "",
        additional_args: str = "",
        timeout_seconds: int = 900,
        engagement_id: str = "",
    ) -> str:
        """SQL injection detection/exploitation via sqlmap (url=, optional data= for POST
        body). Runs --batch. Target an injection-point candidate from recon, not blindly.
        GATED/intrusive — confirm scope. engagement_id= pins the call to a specific engagement."""
        params: dict[str, Any] = {"url": url}
        if data.strip():
            params["data"] = data.strip()
        return execute("sqlmap_scan", params, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def dalfox_xss_scan(
        url: str,
        blind: bool = False,
        custom_payload: str = "",
        additional_args: str = "",
        timeout_seconds: int = 600,
        engagement_id: str = "",
    ) -> str:
        """XSS scanning via dalfox (url=). Mines DOM/params and verifies reflections;
        JSON output parsed into verified (HIGH) vs reflected (lead) findings. blind=true
        adds a blind-XSS callback (needs --blind-url via additional_args).
        engagement_id= pins the call to a specific engagement."""
        params: dict[str, Any] = {"url": url}
        if blind:
            params["blind"] = True
        if custom_payload.strip():
            params["custom_payload"] = custom_payload.strip()
        return execute("dalfox_xss_scan", params, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def jaeles_vulnerability_scan(
        target: str,
        additional_args: str = "",
        timeout_seconds: int = 600,
        engagement_id: str = "",
    ) -> str:
        """Signature-based web vuln scanning via jaeles (target= URL). Complements nuclei
        with a different signature set. engagement_id= pins the call to a specific engagement."""
        return execute("jaeles_vulnerability_scan", {"target": target}, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def sslyze_scan(
        target: str,
        additional_args: str = "",
        timeout_seconds: int = 300,
        engagement_id: str = "",
    ) -> str:
        """TLS/SSL deep scan via SSLyze (target= host or host:port, WSTG-CRYP). Reports weak
        protocols (SSLv2/3, TLS 1.0/1.1), weak ciphers (RC4/3DES/NULL/EXPORT), certificate
        deployment issues, and TLS CVEs (Heartbleed/ROBOT/CCS). The crypto layer tlsx can't
        reach. engagement_id= pins the call to a specific engagement."""
        return execute("sslyze_scan", {"target": target}, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    def graphql_cop_scan(
        url: str,
        additional_args: str = "",
        timeout_seconds: int = 300,
        engagement_id: str = "",
    ) -> str:
        """GraphQL security audit via graphql-cop (url= the /graphql endpoint). Checks
        introspection exposure, field suggestions, batching/aliasing DoS, GET mutations, CSRF,
        deep recursion. Use when recon/scrape finds a GraphQL endpoint. engagement_id= pins the engagement."""
        return execute("graphql_cop_scan", {"url": url}, additional_args=additional_args,
                       timeout_seconds=timeout_seconds, engagement_id=engagement_id)

    tools = (nuclei_scan, nikto_scan, wpscan_analyze, sqlmap_scan, dalfox_xss_scan,
             jaeles_vulnerability_scan, sslyze_scan, graphql_cop_scan)
    for fn in tools:
        mcp.tool(name=fn.__name__)(fn)
    return len(tools)
