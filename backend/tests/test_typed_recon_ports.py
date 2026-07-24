"""Tests for MCP-layer port normalization in typed_recon_network.py."""

from __future__ import annotations

import sys
from pathlib import Path

# Add platform-mcp to path so we can import the module
_MCP_DIR = Path(__file__).resolve().parents[2] / "platform-mcp"
if str(_MCP_DIR) not in sys.path:
    sys.path.insert(0, str(_MCP_DIR))

from typed_recon_network import _normalize_ports_flag


class TestNormalizePortsFlag:
    def test_plain_ports(self) -> None:
        assert _normalize_ports_flag("22,443") == "-p 22,443"

    def test_single_port(self) -> None:
        assert _normalize_ports_flag("80") == "-p 80"

    def test_port_range(self) -> None:
        assert _normalize_ports_flag("1-1024") == "-p 1-1024"

    def test_strips_p_prefix(self) -> None:
        assert _normalize_ports_flag("-p 22,443") == "-p 22,443"

    def test_strips_p_no_space(self) -> None:
        assert _normalize_ports_flag("-p80") == "-p 80"

    def test_strips_ports_prefix(self) -> None:
        assert _normalize_ports_flag("--ports 80,443") == "-p 80,443"

    def test_empty_returns_empty(self) -> None:
        assert _normalize_ports_flag("") == ""
        assert _normalize_ports_flag("   ") == ""

    def test_whitespace_handling(self) -> None:
        assert _normalize_ports_flag("  22,443  ") == "-p 22,443"
