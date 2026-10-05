"""build_recon_markdown renders a full technical report: structural overview
(seed -> sister domains -> subdomains -> IPs) plus — the actual substance —
every tool's raw output, grouped by tool then by target, evidence included
verbatim even when no parser structured it.

Plan 19: tool output lives in OBSERVATIONS (findings now hold only brain
conclusions), so the report is built from observations; these tests seed
observations accordingly. Scanner matches appear as unverified CLAIMS, kept
separate from analyst CONCLUSIONS (VULNERABILITY findings).
"""

from __future__ import annotations

from osprey.schemas.engagement import EngagementCreateRequest
from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.finding import ClaimSeverity, Finding, FindingType
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.engagement_store import get_engagement_store
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store
from osprey.services.markdown_report import build_recon_markdown


def _new_engagement(target: str) -> str:
    return get_engagement_store().create(EngagementCreateRequest(target=target)).id


def _obs(eid: str, otype: ObservationType, *, title: str, target: str, tool: str,
         raw: str = "", tags: list | None = None) -> None:
    details = {"title": title}
    if raw:
        details["raw"] = raw
    get_observation_store().record(Observation(
        engagement_id=eid, type=otype, target=target, source_tool=tool,
        details=details, tags=tags or [],
    ))


def test_unknown_engagement_returns_none():
    assert build_recon_markdown("does-not-exist") is None


def test_report_includes_seed_subdomain_and_vuln_sections():
    eid = _new_engagement("example.com")
    graph = get_engagement_graph()
    graph.ensure_node(engagement_id=eid, asset_type=AssetType.DOMAIN, label="example.com", metadata={"role": "seed"})
    graph.ensure_node(engagement_id=eid, asset_type=AssetType.SUBDOMAIN, label="www.example.com")

    # A brain-authored vulnerability CONCLUSION (findings = conclusions now).
    get_findings_store().add(
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


def test_report_shows_no_conclusions_and_no_claims_messages_when_empty():
    eid = _new_engagement("clean.example.com")
    md = build_recon_markdown(eid)
    assert md is not None
    assert "no analyst/LLM has filed a vulnerability conclusion" in md
    assert "No scanner claims recorded this run" in md


def test_scanner_match_appears_as_unverified_claim_not_a_conclusion():
    eid = _new_engagement("example.com")
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="example.com",
        source_tool="nuclei_scan",
        details={"title": "Exposed .git directory", "claimed_severity": "medium"},
        tags=["nuclei"],
    ))
    md = build_recon_markdown(eid)
    assert md is not None
    assert "Scanner Claims (UNVERIFIED" in md
    assert "Exposed .git directory" in md
    assert "scanner-claimed medium" in md
    # It must NOT be printed as an analyst conclusion.
    assert "no analyst/LLM has filed a vulnerability conclusion" in md


def test_raw_unparsed_observations_appear_with_full_evidence():
    """A prior version pulled only a handful of curated fields into the report;
    raw tool-output observations (crt.sh dumps, nmap banners, cdn probe detail)
    must all appear in the detailed-by-tool section."""
    eid = _new_engagement("example.com")
    _obs(
        eid, ObservationType.RAW, title="crt_sh_query raw output (ok)", target="example.com",
        tool="crt_sh_query",
        raw="mail.example.com\nwww.example.com\nCN=*.example.com issuer=Let's Encrypt",
        tags=["crt_sh_query", "unparsed"],
    )
    md = build_recon_markdown(eid)
    assert md is not None
    assert "## Detailed Findings by Tool" in md
    assert "### crt_sh_query" in md
    assert "CN=*.example.com issuer=Let's Encrypt" in md


def test_tools_executed_table_counts_every_source_tool():
    eid = _new_engagement("example.com")
    for i in range(3):
        _obs(eid, ObservationType.PORT, title=f"example.com:{80 + i}", target="example.com",
             tool="naabu_port_scan")
    md = build_recon_markdown(eid)
    assert md is not None
    assert "## Tools Executed" in md
    assert "| naabu_port_scan | 3 |" in md


def test_emails_and_phones_surfaced_in_contact_section():
    eid = _new_engagement("example.com")
    _obs(eid, ObservationType.EMAIL, title="admin@example.com", target="example.com", tool="theharvester")
    _obs(eid, ObservationType.PHONE, title="+1-555-0100", target="example.com", tool="phoneinfoga")
    md = build_recon_markdown(eid)
    assert md is not None
    assert "## Contact Info / WHOIS / OSINT" in md
    assert "admin@example.com" in md
    assert "+1-555-0100" in md
