"""build_recon_markdown renders a full technical report: structural overview
(seed -> sister domains -> subdomains -> IPs) plus — the actual substance —
every tool's raw output, grouped by tool then by target, evidence included
verbatim even when no parser structured it into a typed finding.
"""

from __future__ import annotations

from osprey.schemas.engagement import EngagementCreateRequest
from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.finding import ClaimSeverity, Finding, FindingType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.engagement_store import get_engagement_store
from osprey.services.findings_store import get_findings_store
from osprey.services.markdown_report import build_recon_markdown


def _new_engagement(target: str) -> str:
    return get_engagement_store().create(EngagementCreateRequest(target=target)).id


def test_unknown_engagement_returns_none():
    assert build_recon_markdown("does-not-exist") is None


def test_report_includes_seed_subdomain_and_vuln_sections():
    eid = _new_engagement("example.com")
    graph = get_engagement_graph()
    graph.ensure_node(engagement_id=eid, asset_type=AssetType.DOMAIN, label="example.com", metadata={"role": "seed"})
    graph.ensure_node(engagement_id=eid, asset_type=AssetType.SUBDOMAIN, label="www.example.com")

    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.SUBDOMAIN,
            title="www.example.com", target="example.com", 
        )
    )
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.PORT,
            title="www.example.com:443", target="www.example.com", 
        )
    )
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.VULNERABILITY,
            title="Slowloris DOS attack (www.example.com:80)", target="www.example.com:80",
            claim_severity=ClaimSeverity.MEDIUM, 
        )
    )

    md = build_recon_markdown(eid)
    assert md is not None
    assert "# Recon Report — example.com" in md
    assert "## Asset Overview" in md
    assert "### Seed Domain" in md
    assert "www.example.com" in md
    assert "## Vulnerabilities" in md
    assert "Slowloris DOS attack" in md
    assert "[medium]" in md


def test_report_shows_no_confirmed_vulns_message_when_none_exist():
    eid = _new_engagement("clean.example.com")
    md = build_recon_markdown(eid)
    assert md is not None
    assert "None confirmed yet" in md


def test_raw_unparsed_findings_appear_with_full_evidence():
    """The actual regression this guards: a prior version only pulled a
    handful of curated fields (ports/services/whois/vulns) into the report —
    hundreds of raw tool-output findings (crt.sh cert dumps, nmap banners,
    cdn probe detail) never appeared anywhere, no matter how much data the
    tools actually returned."""
    eid = _new_engagement("example.com")
    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.OBSERVATION,
            title="crt_sh_query raw output (ok)", target="example.com",
            source_tool="crt_sh_query",
            evidence="mail.example.com\nwww.example.com\nCN=*.example.com issuer=Let's Encrypt",
            tags=["crt_sh_query", "unparsed"],
        )
    )
    md = build_recon_markdown(eid)
    assert md is not None
    assert "## Detailed Findings by Tool" in md
    assert "### crt_sh_query" in md
    assert "CN=*.example.com issuer=Let's Encrypt" in md


def test_raw_data_preferred_over_evidence_when_evidence_is_just_a_command():
    """Older raw-observation findings stored the shell command in `evidence`
    and the tool's actual output in `raw_data` — the report must show the
    real output, not the command that produced it."""
    eid = _new_engagement("example.com")
    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.OBSERVATION,
            title="crt_sh_query raw output (ok)", target="example.com",
            source_tool="crt_sh_query",
            evidence="curl -s 'https://crt.sh/?q=%.example.com&output=json'",
            raw_data='[{"name_value":"mail.example.com"},{"name_value":"admin.example.com"}]',
            tags=["crt_sh_query", "unparsed"],
        )
    )
    md = build_recon_markdown(eid)
    assert md is not None
    assert "mail.example.com" in md
    assert "curl -s" not in md


def test_tools_executed_table_counts_every_source_tool():
    eid = _new_engagement("example.com")
    store = get_findings_store()
    for i in range(3):
        store.add(
            Finding(
                engagement_id=eid, finding_type=FindingType.PORT,
                title=f"example.com:{80 + i}", target="example.com",
                source_tool="naabu_port_scan", 
            )
        )
    md = build_recon_markdown(eid)
    assert md is not None
    assert "## Tools Executed" in md
    assert "| naabu_port_scan | 3 |" in md


def test_emails_and_phones_surfaced_in_contact_section():
    eid = _new_engagement("example.com")
    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.EMAIL,
            title="admin@example.com", target="example.com",
            source_tool="theharvester", 
        )
    )
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.PHONE,
            title="+1-555-0100", target="example.com",
            source_tool="phoneinfoga", 
        )
    )
    md = build_recon_markdown(eid)
    assert md is not None
    assert "## Contact Info / WHOIS / OSINT" in md
    assert "admin@example.com" in md
    assert "+1-555-0100" in md
