"""Regression tests for the recon/network plumbing parser fixes.

Covers the six tools that previously produced only 'unparsed observation'
(whois, masscan, dnsenum, the SMB/AD family) plus the exiftool document-metadata
pivot. These assert that real tool output becomes typed, correctly-graded
Findings with the metadata the graph / coverage engine depend on.
"""

from __future__ import annotations

from pentest_platform.schemas.finding import EvidenceGrade, FindingType
from pentest_platform.services.parsers.registry import (
    ensure_parsers_loaded,
    parse_tool_output,
)

ensure_parsers_loaded()


def _parse(tool: str, out: str, target: str = ""):
    return parse_tool_output(tool, out, engagement_id="e1", run_id="r1", target=target)


def _types(findings):
    return {f.finding_type for f in findings}


def test_whois_extracts_registration_org_dnssec_and_nameservers():
    out = (
        "Domain Name: civilaviation.gov.in\n"
        "Registrar: National Informatics Centre\n"
        "Registrar IANA ID: 800111\n"
        "Creation Date: 2011-02-10T00:00:00Z\n"
        "Registry Expiry Date: 2027-02-10T00:00:00Z\n"
        "Registrant Organization: Ministry of Civil Aviation\n"
        "Name Server: ns1.nic.in\n"
        "Name Server: ns2.nic.in\n"
        "DNSSEC: unsigned\n"
    )
    fs = _parse("whois_lookup", out, target="civilaviation.gov.in")
    assert FindingType.ORGANIZATION in _types(fs)
    reg = next(f for f in fs if f.finding_type == FindingType.OBSERVATION and "WHOIS:" in f.title)
    assert reg.metadata["registrar"] == "National Informatics Centre"
    assert reg.metadata["nameservers"] == "ns1.nic.in,ns2.nic.in"
    # DNSSEC-unsigned is surfaced as its own low-severity finding.
    dnssec = next(f for f in fs if "DNSSEC not configured" in f.title)
    assert dnssec.claim_severity.value == "low"
    assert dnssec.evidence_grade == EvidenceGrade.OBSERVED
    ns = [f for f in fs if f.metadata.get("record_type") == "ns"]
    assert len(ns) == 2


def test_masscan_console_and_greppable_formats():
    out = (
        "Discovered open port 443/tcp on 93.184.216.34\n"
        "Discovered open port 80/tcp on 93.184.216.34\n"
        "Host: 1.2.3.4 () Ports: 22/open/tcp//ssh//\n"
    )
    fs = _parse("masscan_high_speed", out)
    assert len(fs) == 3
    assert all(f.finding_type == FindingType.PORT for f in fs)
    ports = {(f.metadata["ip"], f.metadata["port"]) for f in fs}
    assert ("93.184.216.34", "443") in ports
    assert ("1.2.3.4", "22") in ports


def test_masscan_not_dropped_by_old_rustscan_regex():
    # Guard against regressing to parse_rustscan (which never matched masscan).
    fs = _parse("masscan_high_speed", "Discovered open port 8080/tcp on 10.0.0.9\n")
    assert len(fs) == 1 and fs[0].metadata["port"] == "8080"


def test_dnsenum_records_become_subdomains_hosts_and_dns_observations():
    out = (
        "helisewa.civilaviation.gov.in.  300  IN  A  164.100.115.194\n"
        "civilaviation.gov.in.  3600  IN  NS  ns1.nic.in.\n"
        "civilaviation.gov.in.  3600  IN  MX  10 mail.nic.in.\n"
    )
    fs = _parse("dnsenum_scan", out, target="civilaviation.gov.in")
    types = _types(fs)
    assert FindingType.SUBDOMAIN in types
    assert FindingType.HOST in types
    host = next(f for f in fs if f.finding_type == FindingType.HOST)
    assert host.metadata["ip"] == "164.100.115.194"
    assert host.metadata["hostname"] == "helisewa.civilaviation.gov.in"


def test_smbmap_share_permissions():
    out = (
        "[+] IP: 10.0.0.5:445\tName: DC01\n"
        "\tADMIN$\tNO ACCESS\tRemote Admin\n"
        "\tshared\tREAD, WRITE\tCompany share\n"
    )
    fs = _parse("smbmap_scan", out, target="10.0.0.5")
    writable = next(f for f in fs if f.metadata.get("share") == "shared")
    assert writable.metadata["writable"] is True
    assert "writable" in writable.tags


def test_enum4linux_users_shares_domain():
    out = (
        "Domain Name: CORP\n"
        "[+] Got OS info for 10.0.0.5: Windows Server 2019\n"
        "user:[administrator] rid:[0x1f4]\n"
        "user:[jsmith] rid:[0x450]\n"
        "//10.0.0.5/netlogon\n"
    )
    fs = _parse("enum4linux_scan", out, target="10.0.0.5")
    svc = next(f for f in fs if f.finding_type == FindingType.SERVICE)
    assert svc.metadata["domain"] == "CORP"
    assert svc.metadata["service"] == "smb"
    users = next(f for f in fs if "user(s)" in f.title)
    assert users.metadata["user_count"] == 2


def test_netexec_banner_parses_os_and_domain():
    out = (
        "SMB  10.0.0.5  445  DC01  [*] Windows Server 2019 Build 17763 "
        "(name:DC01) (domain:corp.local) (signing:False) (SMBv1:False)"
    )
    fs = _parse("netexec_scan", out)
    assert len(fs) == 1
    f = fs[0]
    assert f.finding_type == FindingType.SERVICE
    assert f.metadata["domain"] == "corp.local"
    assert "signing_disabled" in f.tags


def test_exiftool_author_is_person_but_software_creator_is_not():
    out = (
        "Author  : Rajesh Kumar\n"
        "Creator  : Microsoft Word\n"
        "GPS Position  : 28.6139 N, 77.2090 E\n"
    )
    fs = _parse("exiftool_extract", out, target="example.com")
    people = [f for f in fs if f.finding_type == FindingType.PERSON]
    assert [f.title for f in people] == ["Rajesh Kumar"]  # Word not treated as a person
    assert any("gps" in (f.metadata.get("exif_tag") or "") for f in fs)
