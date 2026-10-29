"""VULN_TOOLS — tool catalog definitions."""

from __future__ import annotations

from osprey.schemas.tools import ToolCategory, ToolDefinition, ToolSafetyLevel
from osprey.services.tool_definitions._builders import _COMMON_PARAMS, _p, _t


# ---- VULN (2 tools) -------------------------------------------------------

VULN_TOOLS: list[ToolDefinition] = [
    _t("nuclei_scan", ToolCategory.VULN, "nuclei", ToolSafetyLevel.ACTIVE,
       "Template-based vulnerability and exposure scanning.",
       ["templates", "cve", "exposures"],
       {"target": _p("", "Target URL/host"), "severity": _p("", "Severity filter (low/medium/high/critical)"),
        "tags": _p("", "Template tags"), "template": _p("", "Specific template"),
        **_COMMON_PARAMS}),
    _t("jaeles_vulnerability_scan", ToolCategory.VULN, "jaeles", ToolSafetyLevel.ACTIVE,
       "Advanced vulnerability scanning with custom signatures.",
       ["signatures", "vulnerabilities", "custom"],
       {"url": _p("", "Target URL"), "signatures": _p("", "Signature set"),
        "threads": _p("20", "Threads"), **_COMMON_PARAMS}),
    _t("sslyze_scan", ToolCategory.VULN, "sslyze", ToolSafetyLevel.PASSIVE,
       "TLS/SSL deep configuration scan (WSTG-CRYP): weak protocols (SSLv2/3, TLS 1.0/1.1), "
       "weak ciphers (RC4/3DES/NULL/EXPORT), cert deployment, and TLS CVEs (Heartbleed/ROBOT/CCS).",
       ["tls", "ssl", "ciphers", "crypto", "wstg-cryp"],
       {"target": _p("", "host or host:port (default 443)"), **_COMMON_PARAMS},
       install_hint="pip install sslyze (in the Kali image)."),
]
