"""Regressions for the recon-breadth enrichment: reverse DNS (PTR), ASN/netblock,
apex canonicalization, and the tech_dispatch metadata_key existence-match fix.

Pure unit tests — no DB or network required.
"""

from __future__ import annotations

import importlib.util as _iu
from pathlib import Path

from pentest_platform.schemas.finding import FindingType
from pentest_platform.services.parsers.recon_network import (
    parse_asn_enum,
    parse_dnsx_reverse,
)
from pentest_platform.services.parsers.registry import (
    _OUTPUT_PARSERS,
    ensure_parsers_loaded,
)
from pentest_platform.services.target_utils import registrable_apex
from pentest_platform.services.tech_dispatch import _matches
from pentest_platform.services.tool_registry import (
    get_tool_definition,
    resolve_tool_name,
)

_MCP_TOOLS = Path(__file__).resolve().parents[2] / "mcp-servers" / "recon" / "tools"


def _load_tool(name: str):
    spec = _iu.spec_from_file_location(name, _MCP_TOOLS / f"{name}.py")
    mod = _iu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# reverse DNS (dnsx_reverse)
# --------------------------------------------------------------------------- #

def test_dnsx_reverse_build_command_uses_ptr():
    mod = _load_tool("dnsx_reverse")
    cmd = mod.build_command(target="1.1.1.1, 8.8.8.8")
    assert "-ptr" in cmd
    assert "1.1.1.1" in cmd and "8.8.8.8" in cmd
    assert cmd.startswith("bash -c")


def test_dnsx_reverse_parser_emits_hostname_seeds():
    stdout = "1.1.1.1 [PTR] [one.one.one.one]\n8.8.8.8 [PTR] [dns.google]\n"
    findings = parse_dnsx_reverse(stdout, engagement_id="e", run_id="r", target="")
    hosts = {f.title for f in findings}
    assert "one.one.one.one" in hosts
    assert "dns.google" in hosts
    assert all(f.finding_type == FindingType.SUBDOMAIN for f in findings)
    assert all("reverse_dns" in f.tags and "ptr" in f.tags for f in findings)
    # IP is preserved so the graph can link hostname → IP.
    assert any(f.metadata.get("ip") == "1.1.1.1" for f in findings)


def test_dnsx_reverse_parser_ignores_garbage():
    findings = parse_dnsx_reverse("not-an-ip line\n", engagement_id="e", run_id="r")
    # Falls back to a single unparsed observation, never a bogus subdomain.
    assert all(f.finding_type != FindingType.SUBDOMAIN for f in findings)


# --------------------------------------------------------------------------- #
# ASN / netblock (asn_enum)
# --------------------------------------------------------------------------- #

def test_asn_enum_build_command_routes_ip_vs_asn():
    mod = _load_tool("asn_enum")
    assert "whois.cymru.com" in mod.build_command(target="1.1.1.1")
    assert "whois.radb.net" in mod.build_command(asn="13335")
    # An ASN passed in the target slot is still routed to RADb.
    assert "whois.radb.net" in mod.build_command(target="AS13335")


def test_asn_enum_parser_cymru_emits_asn_and_netblock():
    stdout = (
        "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
        "13335   | 1.1.1.1          | 1.1.1.0/24          | US | ARIN     | 2011-08-11 | CLOUDFLARENET, US\n"
    )
    findings = parse_asn_enum(stdout, engagement_id="e", run_id="r")
    assert any("AS13335" in f.title for f in findings)
    netblocks = [f for f in findings if f.metadata.get("cidr")]
    assert netblocks and netblocks[0].metadata["cidr"] == "1.1.1.0/24"
    assert any("netblock" in f.tags for f in findings)


def test_asn_enum_parser_radb_lists_prefixes():
    stdout = (
        "route:      1.1.1.0/24\ndescr:      Cloudflare\norigin:     AS13335\n\n"
        "route:      1.0.0.0/24\norigin:     AS13335\n"
    )
    findings = parse_asn_enum(stdout, engagement_id="e", run_id="r")
    cidrs = {f.metadata.get("cidr") for f in findings}
    assert cidrs == {"1.1.1.0/24", "1.0.0.0/24"}
    assert all("asn" in f.tags for f in findings)


# --------------------------------------------------------------------------- #
# registration wiring
# --------------------------------------------------------------------------- #

def test_new_tools_registered_and_parsed():
    ensure_parsers_loaded()
    for name in ("dnsx_reverse", "asn_enum"):
        td = get_tool_definition(name)
        assert td is not None, f"{name} not in registry"
        assert td.mcp_server.value == "recon"
        assert name in _OUTPUT_PARSERS, f"{name} has no parser"


def test_tool_aliases_resolve():
    assert resolve_tool_name("reverse_dns") == "dnsx_reverse"
    assert resolve_tool_name("ptr_lookup") == "dnsx_reverse"
    assert resolve_tool_name("asn") == "asn_enum"
    assert resolve_tool_name("netblock") == "asn_enum"


# --------------------------------------------------------------------------- #
# apex canonicalization
# --------------------------------------------------------------------------- #

def test_registrable_apex():
    assert registrable_apex("sub.scanme.nmap.org") == "nmap.org"
    assert registrable_apex("a.b.example.co.uk") == "example.co.uk"
    assert registrable_apex("api.staging.gallup.com.pk") == "gallup.com.pk"
    assert registrable_apex("www.example.com") == "example.com"
    assert registrable_apex("example.com") == "example.com"
    # IPs pass through untouched.
    assert registrable_apex("1.2.3.4") == "1.2.3.4"
    # URL forms are normalized first.
    assert registrable_apex("https://mail.example.com/x") == "example.com"


# --------------------------------------------------------------------------- #
# tech_dispatch metadata_key existence-match fix
# --------------------------------------------------------------------------- #

def _host_finding_with_ip():
    return parse_asn_enum(
        "13335 | 1.1.1.1 | 1.1.1.0/24 | US | ARIN | 2011 | CLOUDFLARENET",
        engagement_id="e",
        run_id="r",
    )


def test_metadata_key_existence_match():
    # A finding carrying non-empty ip/cidr metadata should satisfy a bare
    # metadata_key match (the previous code required contains/value and never
    # matched an existence-only rule).
    findings = _host_finding_with_ip()
    match = {"finding_type": "observation", "metadata_key": "cidr", "min_count": 1}
    assert _matches(match, findings, graph=None, engagement_id="e") is True


def test_metadata_key_existence_no_match_when_absent():
    findings = parse_dnsx_reverse(
        "1.1.1.1 [PTR] [one.one.one.one]", engagement_id="e", run_id="r"
    )
    match = {"metadata_key": "cidr", "min_count": 1}
    # PTR findings carry no cidr metadata → should not match.
    assert _matches(match, findings, graph=None, engagement_id="e") is False
