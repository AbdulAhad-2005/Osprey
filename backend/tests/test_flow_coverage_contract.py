"""Plan 19 Phase 2 — permanent coverage guarantees for the deterministic floor.

These began (Phase 1) as xfail-strict contracts documenting that the no-LLM
engine never reached vulnerability analysis. Phase 2 repointed ``tech_dispatch``
off the (empty, in no-LLM) ``findings_store`` onto observations/graph and removed
the redundant vuln phase-unlock gate — so they now pass and are promoted to hard
guarantees: coverage may not silently regress.

Everything runs through the REAL decision path (``investigation_capabilities.
list_step`` + the deterministic driver's max-priority rule, via
``benchmark.flow_replay``), replaying recorded-shape tool output through real
ingestion. No live tools, no network, no LLM.
"""
from __future__ import annotations

import asyncio

from osprey.schemas.benchmark import Recording, ToolCallRecord
from osprey.services.benchmark.flow_replay import offered_after_ingest

_TARGET = "flowtest.example"


def _live_wordpress_host() -> Recording:
    """A resolved, live web host running WordPress — real httpx_probe output
    shape (verified against parsers/recon_network.parse_httpx: httpx emits both
    a URL and a TECHNOLOGY observation when tech is detected). Enough state that
    a pentester runs nuclei + a CMS scanner immediately; the deterministic floor
    must reach the same conclusion mechanically, from observations alone."""
    return Recording(
        name="contract-live-wordpress-host",
        target=_TARGET,
        synthetic=True,
        calls=[
            ToolCallRecord(
                tool_name="httpx_probe",
                target=_TARGET,
                command="httpx -sc -title -td",
                stdout=f"https://{_TARGET} [200] [Welcome] [nginx,WordPress]\n",
                returncode=0,
                success=True,
                stdout_source="none",
            )
        ],
    )


def _archived_parameterized_url() -> Recording:
    """A real archived URL carrying a query parameter — real waybackurls_
    discovery output shape (one URL per line). This is the dominant real-world
    source of injectable requests (plan 19): PHP/tech detection ALONE must
    never trigger sqlmap (that was the confirmed "sqlmap against a bare
    domain root, finds nothing" bug) — only a genuinely discovered parameter
    may."""
    return Recording(
        name="contract-archived-parameterized-url",
        target=_TARGET,
        synthetic=True,
        calls=[
            ToolCallRecord(
                tool_name="waybackurls_discovery",
                target=_TARGET,
                command="waybackurls",
                stdout=f"https://{_TARGET}/article.php?id=5\n",
                returncode=0,
                success=True,
                stdout_source="none",
            )
        ],
    )


def _offered_for(recording: Recording) -> set[str]:
    return asyncio.run(offered_after_ingest(recording)).offered_tools()


def test_live_web_host_reaches_nuclei():
    """A live web application with a detected technology yields a nuclei
    opportunity from the deterministic floor — no finding, no LLM, no priority
    unlock. The keystone of plan 19."""
    assert "nuclei_scan" in _offered_for(_live_wordpress_host())


def test_wordpress_reaches_wpscan():
    """WordPress fingerprinted on a live host yields a wpscan opportunity — the
    technology-triggered specialist scan every pentester runs on a WP site."""
    assert "wpscan_analyze" in _offered_for(_live_wordpress_host())


def test_parameterized_request_reaches_sqlmap():
    """An archived URL carrying a real query parameter yields a sqlmap
    opportunity — SQLi testing is mandatory coverage where an injectable
    input surface exists (never sqlmap against a bare domain root)."""
    assert "sqlmap_scan" in _offered_for(_archived_parameterized_url())
