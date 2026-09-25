"""investigation_director.run_to_completion — bounded pass loop + real
finding-title visibility (not just counts), and the exploit-queue refresh
folded in.

Ported from the deleted ``surface_expansion.run_expansion_to_fixpoint``
(plans/harness/09-dual-mode-planner.md Step 2b: port the tests FIRST, prove
parity, only then delete — not a rewrite from memory). The capability being
looped (``run_expansion_pass``) is unchanged and still patched at its
original home (``osprey.services.surface_expansion.run_expansion_pass``) —
``run_to_completion`` imports it lazily inside the function body, so patching
the origin module still intercepts it exactly as before the move.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from osprey.services.investigation_director import run_to_completion
from osprey.services.surface_expansion import ExpansionDelta


def _run(coro):
    return asyncio.run(coro)


def _delta(engagement_id="e1", frontier=1, new_nodes=1, new_edges=1, exhausted=False, total_passes=1):
    return ExpansionDelta(
        engagement_id=engagement_id, frontier_processed=frontier, new_nodes=new_nodes,
        new_edges=new_edges, exhausted=exhausted, total_passes=total_passes,
    )


def test_stops_at_exhaustion_before_max_passes():
    deltas = [_delta(exhausted=False), _delta(exhausted=True, total_passes=2)]
    with patch("osprey.services.surface_expansion.run_expansion_pass", new_callable=AsyncMock) as mock_pass, \
         patch("osprey.services.findings_store.get_findings_store") as mock_store, \
         patch("osprey.services.exploit_pipeline.scan_for_candidates", return_value=[]), \
         patch("osprey.services.exploit_candidate_store.get_exploit_candidate_store") as mock_cand:
        mock_pass.side_effect = deltas
        mock_store.return_value.list.return_value = []
        mock_cand.return_value.list_for_engagement.return_value = []
        report = _run(run_to_completion(engagement_id="e1", run_id="r1", max_passes=5))
        assert len(report.passes) == 2
        assert report.exhausted is True
        assert report.stopped_reason == "exhausted"
        assert mock_pass.await_count == 2  # stopped early, not all 5


def test_stops_at_max_passes_when_never_exhausted():
    with patch("osprey.services.surface_expansion.run_expansion_pass", new_callable=AsyncMock) as mock_pass, \
         patch("osprey.services.findings_store.get_findings_store") as mock_store, \
         patch("osprey.services.exploit_pipeline.scan_for_candidates", return_value=[]), \
         patch("osprey.services.exploit_candidate_store.get_exploit_candidate_store") as mock_cand:
        mock_pass.return_value = _delta(exhausted=False, frontier=3)
        mock_store.return_value.list.return_value = []
        mock_cand.return_value.list_for_engagement.return_value = []
        report = _run(run_to_completion(engagement_id="e1", run_id="r1", max_passes=3))
        assert len(report.passes) == 3
        assert report.exhausted is False
        assert report.stopped_reason == "max_passes"


def test_stops_early_on_empty_frontier_without_burning_max_passes():
    with patch("osprey.services.surface_expansion.run_expansion_pass", new_callable=AsyncMock) as mock_pass, \
         patch("osprey.services.findings_store.get_findings_store") as mock_store, \
         patch("osprey.services.exploit_pipeline.scan_for_candidates", return_value=[]), \
         patch("osprey.services.exploit_candidate_store.get_exploit_candidate_store") as mock_cand:
        mock_pass.return_value = _delta(frontier=0, new_nodes=0, new_edges=0, exhausted=False)
        mock_store.return_value.list.return_value = []
        mock_cand.return_value.list_for_engagement.return_value = []
        report = _run(run_to_completion(engagement_id="e1", run_id="r1", max_passes=5))
        assert len(report.passes) == 1
        assert mock_pass.await_count == 1


def test_new_finding_titles_captured_per_pass_not_just_counts():
    f_before = MagicMock(id="f1", title="old finding")
    f_after_1 = MagicMock(id="f2", title="new.subdomain.test")
    with patch("osprey.services.surface_expansion.run_expansion_pass", new_callable=AsyncMock) as mock_pass, \
         patch("osprey.services.findings_store.get_findings_store") as mock_store, \
         patch("osprey.services.exploit_pipeline.scan_for_candidates", return_value=[]), \
         patch("osprey.services.exploit_candidate_store.get_exploit_candidate_store") as mock_cand:
        mock_pass.return_value = _delta(exhausted=True)
        mock_store.return_value.list.side_effect = [[f_before], [f_before, f_after_1]]
        mock_cand.return_value.list_for_engagement.return_value = []
        report = _run(run_to_completion(engagement_id="e1", run_id="r1"))
        assert report.passes[0].new_finding_titles == ["new.subdomain.test"]


def test_new_candidates_surfaced_from_the_same_call():
    new_cand = MagicMock(id="c1", promotion_trigger="cve_match", evidence_summary="CVE-2024-1")
    with patch("osprey.services.surface_expansion.run_expansion_pass", new_callable=AsyncMock) as mock_pass, \
         patch("osprey.services.findings_store.get_findings_store") as mock_store, \
         patch("osprey.services.exploit_pipeline.scan_for_candidates", return_value=[new_cand]), \
         patch("osprey.services.exploit_candidate_store.get_exploit_candidate_store") as mock_cand:
        mock_pass.return_value = _delta(exhausted=True)
        mock_store.return_value.list.return_value = []
        mock_cand.return_value.list_for_engagement.return_value = []  # none existed before
        report = _run(run_to_completion(engagement_id="e1", run_id="r1"))
        assert report.new_candidate_count == 1
        assert "cve_match" in report.new_candidate_samples[0]


def test_no_engagement_id_is_safe_noop():
    report = _run(run_to_completion(engagement_id="", run_id="r1"))
    assert report.passes == []


def test_vuln_dispatch_never_called_when_nothing_makes_it_worthwhile():
    """Parity with the old include_vuln_dispatch=False default: with no real
    evidence for this engagement, priority.should_unlock_phase("vuln") is
    False, so the director never calls the vuln-dispatch capability — proven
    by NOT mocking it at all; a call would hit a live tool and fail/hang."""
    with patch("osprey.services.surface_expansion.run_expansion_pass", new_callable=AsyncMock) as mock_pass, \
         patch("osprey.services.findings_store.get_findings_store") as mock_store, \
         patch("osprey.services.exploit_pipeline.scan_for_candidates", return_value=[]), \
         patch("osprey.services.exploit_candidate_store.get_exploit_candidate_store") as mock_cand:
        mock_pass.return_value = _delta(exhausted=True)
        mock_store.return_value.list.return_value = []
        mock_cand.return_value.list_for_engagement.return_value = []
        report = _run(run_to_completion(engagement_id="vuln-dispatch-parity-test", run_id="r1"))
        assert report.stopped_reason == "exhausted"
