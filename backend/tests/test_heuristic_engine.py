"""Tests for the no-LLM heuristic dispatch engine's remaining surface.

``select_next_dispatch``/``dispatch_key``/``run_dispatch_stage``/
``run_dispatch_step`` were deleted (Plan 18 Workstream B) — they were the
vuln-side equivalent of the pre-Plan-17 batching anti-pattern (a whole
dispatch loop hidden behind one call) and, once
``investigation_capabilities.list_step`` started building tool/params
directly onto each opportunity, they had no live caller at all. Only the
category-blocklist categorization survives here.
"""

from __future__ import annotations

from osprey.services import heuristic_engine as he


def test_non_autonomous_categories_are_the_downstream_ones():
    assert he.NON_AUTONOMOUS_CATEGORIES == frozenset({"exploit", "creds", "postex"})


def test_engine_may_autorun_allows_passive_tool_in_a_gated_category():
    # searchsploit_lookup is cataloged under exploit but is read-only (PASSIVE),
    # so the engine may auto-run it for CVE-candidate research (E1.1/E2).
    assert he.engine_may_autorun("searchsploit_lookup") is True


def test_engine_may_autorun_still_gates_intrusive_tools():
    assert he.engine_may_autorun("metasploit_run") is False  # active exploit
    assert he.engine_may_autorun("hydra_attack") is False    # creds attack


def test_engine_may_autorun_allows_ordinary_recon():
    assert he.engine_may_autorun("httpx_probe") is True
    assert he.engine_may_autorun("nmap_service_scan") is True
