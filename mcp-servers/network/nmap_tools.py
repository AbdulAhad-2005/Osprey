"""
Register hero nmap tools from nmap_wrapper.py on a FastMCP instance.

These replace the simplified harvested nmap_scan — full raw output + XML + evasion.
"""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP

from nmap_wrapper import EvasionOptions, NmapError, NmapScanner

_scanner: NmapScanner | None = None


def _get_scanner() -> NmapScanner:
    global _scanner
    if _scanner is None:
        _scanner = NmapScanner()
    return _scanner


def register_nmap_tools(mcp: FastMCP) -> None:
    @mcp.tool(name="nmap_syn_scan")
    def nmap_syn_scan(
        target: str,
        ports: Optional[str] = None,
        timing: Optional[str] = None,
        extra_args: Optional[str] = None,
    ) -> dict:
        """TCP SYN scan (-sS). Full raw + XML output via NmapScanner."""
        try:
            evasion = EvasionOptions(timing=timing) if timing else None
            return _get_scanner().syn_scan(
                target, ports=ports, evasion=evasion, extra_args=extra_args
            )
        except NmapError as exc:
            return {"success": False, "error": str(exc), "tool_name": "nmap_syn_scan"}

    @mcp.tool(name="nmap_service_scan")
    def nmap_service_scan(
        target: str,
        ports: Optional[str] = None,
        extra_args: Optional[str] = None,
    ) -> dict:
        """Version + default scripts (-sV -sC). Full raw + XML output."""
        try:
            return _get_scanner().version_scan(target, ports=ports, extra_args=extra_args)
        except NmapError as exc:
            return {"success": False, "error": str(exc), "tool_name": "nmap_service_scan"}

    @mcp.tool(name="nmap_custom_scan")
    def nmap_custom_scan(
        target: str,
        flags: str,
        privileged: bool = False,
    ) -> dict:
        """Custom nmap flags (LLM escape hatch). Full raw + XML output."""
        try:
            return _get_scanner().custom_scan(target, flags=flags, privileged=privileged)
        except NmapError as exc:
            return {"success": False, "error": str(exc), "tool_name": "nmap_custom_scan"}
