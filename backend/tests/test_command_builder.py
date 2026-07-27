"""Tests for Nmap command normalization in command_builder.py."""

from __future__ import annotations

from pentest_platform.services.command_builder import _build_nmap_command
from pentest_platform.services.target_utils import normalize_ports_value as _normalize_ports_value


class TestNormalizePortsValue:
    def test_strips_p_prefix(self) -> None:
        assert _normalize_ports_value("-p 22,443") == "22,443"
        assert _normalize_ports_value("-p 80") == "80"

    def test_strips_p_prefix_no_space(self) -> None:
        assert _normalize_ports_value("-p80") == "80"

    def test_plain_ports_unchanged(self) -> None:
        assert _normalize_ports_value("22,443,8080") == "22,443,8080"

    def test_empty_returns_empty(self) -> None:
        assert _normalize_ports_value("") == ""
        assert _normalize_ports_value("   ") == ""

    def test_strips_leading_dash(self) -> None:
        assert _normalize_ports_value("-22") == "22"

    def test_strips_ports_prefix(self) -> None:
        assert _normalize_ports_value("--ports 80,443") == "80,443"
        assert _normalize_ports_value("--ports 80") == "80"


class TestBuildNmapCustomScan:
    def test_custom_scan_ports_via_additional_args(self) -> None:
        cmd = _build_nmap_command(
            "nmap_custom_scan",
            {"target": "10.0.0.1", "additional_args": "-p 22,443"},
        )
        assert "-p 22,443" in cmd
        assert "nmap" in cmd
        assert "10.0.0.1" in cmd

    def test_custom_scan_with_flags_only(self) -> None:
        cmd = _build_nmap_command(
            "nmap_custom_scan",
            {"target": "10.0.0.1", "flags": "-sT -p 80"},
        )
        assert "-p 80" in cmd
        assert "-sT" in cmd

    def test_custom_scan_default_when_empty_flags(self) -> None:
        cmd = _build_nmap_command(
            "nmap_custom_scan",
            {"target": "10.0.0.1", "flags": ""},
        )
        assert "-sT" in cmd
        assert "-Pn" in cmd
        assert "--unprivileged" in cmd

    def test_custom_scan_ports_via_flags_field(self) -> None:
        cmd = _build_nmap_command(
            "nmap_custom_scan",
            {"target": "10.0.0.1", "flags": "-sV -p 80,443"},
        )
        assert "-p 80,443" in cmd
        assert "-sV" in cmd


class TestBuildNmapSynScan:
    def test_syn_scan_ports_via_additional_args(self) -> None:
        cmd = _build_nmap_command(
            "nmap_syn_scan",
            {"target": "10.0.0.1", "additional_args": "-p 22,443"},
        )
        assert "-p 22,443" in cmd
        assert "-sT" in cmd

    def test_syn_scan_no_ports_no_fast(self) -> None:
        cmd = _build_nmap_command(
            "nmap_syn_scan",
            {"target": "10.0.0.1"},
        )
        assert "-sT" in cmd
        assert "-F" not in cmd

    def test_syn_scan_privileged(self) -> None:
        cmd = _build_nmap_command(
            "nmap_syn_scan",
            {"target": "10.0.0.1", "privileged": True, "additional_args": "-p 80"},
        )
        assert "sudo" in cmd
        assert "-sS" in cmd

    def test_syn_scan_timing(self) -> None:
        cmd = _build_nmap_command(
            "nmap_syn_scan",
            {"target": "10.0.0.1", "timing": "T4"},
        )
        assert "-T4" in cmd

    def test_syn_scan_ports_via_raw_param(self) -> None:
        cmd = _build_nmap_command(
            "nmap_syn_scan",
            {"target": "10.0.0.1", "ports": "22,443"},
        )
        assert "-p 22,443" in cmd


class TestBuildNmapServiceScan:
    def test_service_scan_ports_via_additional_args(self) -> None:
        cmd = _build_nmap_command(
            "nmap_service_scan",
            {"target": "10.0.0.1", "additional_args": "-p 80,443"},
        )
        assert "-p 80,443" in cmd
        assert "-sV" in cmd
        assert "-sC" in cmd

    def test_service_scan_no_ports_no_fast(self) -> None:
        cmd = _build_nmap_command(
            "nmap_service_scan",
            {"target": "10.0.0.1"},
        )
        assert "-sV" in cmd
        assert "-F" not in cmd

    def test_service_scan_ports_via_raw_param(self) -> None:
        cmd = _build_nmap_command(
            "nmap_service_scan",
            {"target": "10.0.0.1", "ports": "80,443"},
        )
        assert "-p 80,443" in cmd
