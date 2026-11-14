"""domain_hunter shares its "sister_discovery" opportunity bucket with
crt_sh_query, and "domain_only" with whois_lookup/dnsenum_scan — all of
which used to get the SAME 60s ceiling. domain_hunter queries several
independent signal sources then live-probes every candidate (90s-budgeted
sweep), structurally heavier than its single-source bucket-mates — measured
at ~110s for a large conglomerate seed. config/expansion.yaml gives it its
own per-entry timeout override; every other tool in the same bucket keeps
the shared default.
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


def test_domain_hunter_gets_a_longer_timeout_than_its_bucket_mates():
    eid = _make_engagement("dh-timeout.test")
    get_engagement_graph().ensure_node(engagement_id=eid, asset_type=AssetType.DOMAIN, label="dh-timeout.test")

    step = investigation_capabilities.list_step(eid)
    by_tool = {o.tool: o.timeout for o in step.opportunities if o.tool}

    assert by_tool.get("domain_hunter") == 130
    # Its single-source bucket-mates keep the original, tighter default.
    for tool in ("crt_sh_query", "whois_lookup", "dnsenum_scan"):
        assert by_tool.get(tool) == 60, f"{tool} timeout unexpectedly changed: {by_tool.get(tool)}"
