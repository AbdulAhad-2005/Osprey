"""Per-asset claims (Stage 7) — best-effort in-flight marker for parallel
agents. Same advisory contract as the rest of tool_coverage_store: a
failed claim is a signal, never a hard block.
"""

from __future__ import annotations

from osprey.services.tool_coverage_store import get_tool_coverage_store


def test_first_claim_succeeds():
    store = get_tool_coverage_store()
    assert store.try_claim(engagement_id="e-claim-1", tool_name="nmap_custom_scan", asset="host.test", run_id="run-a")


def test_second_concurrent_claim_fails_while_first_held():
    store = get_tool_coverage_store()
    assert store.try_claim(engagement_id="e-claim-2", tool_name="nmap_custom_scan", asset="host.test", run_id="run-a")
    assert not store.try_claim(engagement_id="e-claim-2", tool_name="nmap_custom_scan", asset="host.test", run_id="run-b")


def test_claim_succeeds_again_after_release():
    store = get_tool_coverage_store()
    store.try_claim(engagement_id="e-claim-3", tool_name="nmap_custom_scan", asset="host.test", run_id="run-a")
    store.release(engagement_id="e-claim-3", tool_name="nmap_custom_scan", asset="host.test")
    assert store.try_claim(engagement_id="e-claim-3", tool_name="nmap_custom_scan", asset="host.test", run_id="run-b")


def test_same_run_id_can_reclaim_its_own_asset():
    store = get_tool_coverage_store()
    store.try_claim(engagement_id="e-claim-4", tool_name="nmap_custom_scan", asset="host.test", run_id="run-a")
    assert store.try_claim(engagement_id="e-claim-4", tool_name="nmap_custom_scan", asset="host.test", run_id="run-a")


def test_different_assets_dont_collide():
    store = get_tool_coverage_store()
    assert store.try_claim(engagement_id="e-claim-5", tool_name="nmap_custom_scan", asset="host-a.test", run_id="run-a")
    assert store.try_claim(engagement_id="e-claim-5", tool_name="nmap_custom_scan", asset="host-b.test", run_id="run-b")
