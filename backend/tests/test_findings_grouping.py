"""Tests for findings_store.list_grouped — collapsing the same issue firing
on many host:port instances (or the same URL-crawl pattern across many
paths) into one row with an affected-target list, instead of dozens of
near-identical rows a human has to notice are the same thing.
"""

from __future__ import annotations

import uuid

from osprey.schemas.finding import ClaimSeverity, Finding, FindingType
from osprey.services.findings_store import get_findings_store


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def test_list_ranks_by_confidence_and_severity_before_recency():
    """The gap a real operator transcript surfaced: FindingsStore.list()
    ordered purely by created_at, so 118 confidence=hypothesis, sev=none
    sister-domain guesses (domain_hunter, filed early) outranked 2
    confidence=confirmed subdomains (subfinder_scan) in a truncated,
    limit-bounded list — an operator/LLM scanning the first page of results
    never reached what actually mattered. Confirmed/high-severity findings
    must sort first regardless of creation order, with recency only as a
    tiebreaker among equally-ranked items."""
    eid = _eid()
    store = get_findings_store()
    # Filed in an order that would look "correct" under pure created_at
    # ordering but is exactly backwards for what an operator wants to see
    # first — the noisy hypothesis-tier guess is created LAST (most recent).
    store.add(Finding(
        engagement_id=eid, finding_type=FindingType.HOST, title="lookalike-domain.example",
        target="lookalike-domain.example", source_tool="domain_hunter",
        confidence="hypothesis", claim_severity=ClaimSeverity.NONE,
    ))
    store.add(Finding(
        engagement_id=eid, finding_type=FindingType.VULNERABILITY, title="Critical RCE",
        target="app.example.com", source_tool="nuclei_scan",
        confidence="confirmed", claim_severity=ClaimSeverity.CRITICAL,
    ))
    store.add(Finding(
        engagement_id=eid, finding_type=FindingType.SUBDOMAIN, title="confirmed-real.example",
        target="confirmed-real.example", source_tool="subfinder_scan",
        confidence="confirmed", claim_severity=ClaimSeverity.NONE,
    ))

    findings = store.list(engagement_id=eid, limit=50)
    titles = [f.title for f in findings]
    assert titles[0] == "Critical RCE"
    assert titles.index("confirmed-real.example") < titles.index("lookalike-domain.example")


def test_same_nse_script_across_many_ports_collapses_to_one_group():
    eid = _eid()
    store = get_findings_store()
    for host_port in ("www.example.com:80", "www.example.com:443", "www.example.com:8080"):
        store.add(
            Finding(
                engagement_id=eid,
                finding_type=FindingType.VULNERABILITY,
                title=f"http-csrf output ({host_port})",
                target=host_port,
                source_tool="nmap_custom_scan",
                claim_severity=ClaimSeverity.LOW,
            )
        )
    groups, total_groups, total_findings = store.list_grouped(engagement_id=eid, exclude_noise=False)
    assert len(groups) == 1
    g = groups[0]
    assert g.title == "http-csrf output"
    assert g.count == 3
    assert set(g.affected_targets) == {"www.example.com:80", "www.example.com:443", "www.example.com:8080"}


def test_distinct_issues_stay_separate_groups():
    eid = _eid()
    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.VULNERABILITY,
            title="http-csrf output (a.com:80)", target="a.com:80", source_tool="nmap_custom_scan",
            claim_severity=ClaimSeverity.LOW, 
        )
    )
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.VULNERABILITY,
            title="http-sql-injection output (a.com:443)", target="a.com:443", source_tool="nmap_custom_scan",
            claim_severity=ClaimSeverity.HIGH, 
        )
    )
    groups, total_groups, total_findings = store.list_grouped(engagement_id=eid, exclude_noise=False)
    assert len(groups) == 2


def test_groups_sorted_worst_severity_first():
    eid = _eid()
    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.VULNERABILITY,
            title="low issue (a.com:80)", target="a.com:80", source_tool="t",
            claim_severity=ClaimSeverity.LOW, 
        )
    )
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.VULNERABILITY,
            title="critical issue (a.com:443)", target="a.com:443", source_tool="t",
            claim_severity=ClaimSeverity.CRITICAL, 
        )
    )
    groups, total_groups, total_findings = store.list_grouped(engagement_id=eid, exclude_noise=False)
    assert groups[0].severity == "critical"
    assert groups[1].severity == "low"


def test_bulk_crawled_urls_collapse_to_parent_path():
    eid = _eid()
    store = get_findings_store()
    for i in range(5):
        store.add(
            Finding(
                engagement_id=eid, finding_type=FindingType.URL,
                title=f"https://elections.example.com/na-{i}/", target="elections.example.com",
                source_tool="waybackurls_discovery", 
            )
        )
    groups, total_groups, total_findings = store.list_grouped(engagement_id=eid, exclude_noise=False)
    assert len(groups) == 1
    assert groups[0].count == 5
    assert groups[0].title == "https://elections.example.com/*"


def test_group_limit_caps_display_but_reports_true_totals():
    """The actual regression this guards: a prior version silently reported
    len(shown_groups) as if it were the total, understating scope whenever
    group_limit truncated — e.g. claiming "1113 findings" when 1597 existed."""
    eid = _eid()
    store = get_findings_store()
    for i in range(5):
        store.add(
            Finding(
                engagement_id=eid, finding_type=FindingType.VULNERABILITY,
                title=f"distinct issue {i} (a.com:80)", target="a.com:80", source_tool="t",
                claim_severity=ClaimSeverity.LOW, 
            )
        )
    groups, total_groups, total_findings = store.list_grouped(
        engagement_id=eid, exclude_noise=False, group_limit=2,
    )
    assert len(groups) == 2
    assert total_groups == 5
    assert total_findings == 5


def test_severity_within_a_group_takes_the_worst_seen():
    eid = _eid()
    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.VULNERABILITY,
            title="issue (a.com:80)", target="a.com:80", source_tool="t",
            claim_severity=ClaimSeverity.INFO, 
        )
    )
    store.add(
        Finding(
            engagement_id=eid, finding_type=FindingType.VULNERABILITY,
            title="issue (a.com:443)", target="a.com:443", source_tool="t",
            claim_severity=ClaimSeverity.HIGH, 
        )
    )
    groups, total_groups, total_findings = store.list_grouped(engagement_id=eid, exclude_noise=False)
    assert len(groups) == 1
    assert groups[0].severity == "high"
