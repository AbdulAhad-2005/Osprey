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
