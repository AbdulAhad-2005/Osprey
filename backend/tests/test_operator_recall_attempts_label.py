"""attempts_for_asset's display text — a real operator transcript surfaced
this: it said "findings=8" for a tool that only ever produces Observations
(Plan 02's split), while platform_findings honestly showed 0 — a direct,
misleading contradiction. tool_coverage_store's own findings_count field
name stays as-is (a bigger, separately-scoped rename), but the text an
operator/LLM actually reads must not claim something confidence_for never
earned.
"""

from __future__ import annotations

from osprey.services.operator_recall import attempts_for_asset
from osprey.services.tool_coverage_store import get_tool_coverage_store


def test_attempts_text_says_signals_not_findings():
    eid = "attempts-label-test"
    get_tool_coverage_store().record(
        engagement_id=eid, tool_name="domain_hunter", asset="geo.tv",
        run_id="r1", findings_count=8, success=True,
    )
    result = attempts_for_asset(eid, asset="geo.tv")
    assert "signals=8" in result["text"]
    assert "findings=8" not in result["text"]
