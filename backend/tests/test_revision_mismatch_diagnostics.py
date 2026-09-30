"""A stale-investigation-revision 409 previously carried no information about
WHAT actually changed — just two opaque hashes. A persistent replan loop
(observed live against geo.tv, twice, on different opportunities) had no way
to be diagnosed beyond "it happened again." list_step() now retains a small,
bounded, diagnostic-only cache of the basis behind its last few revisions per
engagement, so a mismatch can report which part of state (nodes/
opportunities/active_jobs) actually moved.
"""

from __future__ import annotations

from osprey.schemas.engagement_graph import AssetType
from osprey.services import investigation_capabilities
from osprey.services.engagement_graph import get_engagement_graph


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_diagnose_reports_no_tracked_field_changed_when_none_did():
    eid = _make_engagement("diag-stable.test")
    get_engagement_graph().ensure_node(engagement_id=eid, asset_type=AssetType.DOMAIN, label="diag-stable.test")

    step1 = investigation_capabilities.list_step(eid)
    step2 = investigation_capabilities.list_step(eid)

    assert step1.revision == step2.revision  # nothing changed — same revision, not exercising the diff path
    diff = investigation_capabilities.diagnose_revision_mismatch(eid, step1.revision, step1.revision)
    assert "changed=[]" in diff or "not retained" not in diff


def test_diagnose_identifies_the_opportunities_field_when_a_node_is_added():
    eid = _make_engagement("diag-changed.test")
    get_engagement_graph().ensure_node(engagement_id=eid, asset_type=AssetType.DOMAIN, label="diag-changed.test")
    step1 = investigation_capabilities.list_step(eid)

    get_engagement_graph().ensure_node(engagement_id=eid, asset_type=AssetType.SUBDOMAIN, label="new.diag-changed.test")
    step2 = investigation_capabilities.list_step(eid)

    assert step1.revision != step2.revision
    diff = investigation_capabilities.diagnose_revision_mismatch(eid, step1.revision, step2.revision)
    assert "not retained" not in diff
    assert "nodes" in diff or "opportunities" in diff


def test_diagnose_reports_unretained_basis_for_an_unknown_revision():
    eid = _make_engagement("diag-unknown.test")
    get_engagement_graph().ensure_node(engagement_id=eid, asset_type=AssetType.DOMAIN, label="diag-unknown.test")
    step = investigation_capabilities.list_step(eid)

    diff = investigation_capabilities.diagnose_revision_mismatch(eid, "rev_totally_made_up", step.revision)

    assert "not retained" in diff
