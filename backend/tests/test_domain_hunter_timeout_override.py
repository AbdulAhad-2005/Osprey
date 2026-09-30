"""domain_hunter shares its "sister_discovery" opportunity bucket with
crt_sh_query, and "domain_only" with whois_lookup/dnsenum_scan — all of
which used to get the SAME 60s ceiling. domain_hunter queries ~10
independent external signal sources (crt.sh, Wikidata, ASN reverse-lookup,
RDAP, certspotter, DNS, SPF/DMARC, reverse-NS), structurally heavier than
its single-source bucket-mates, and landed consistently at ~63-64s in
production — not occasional bad luck, a ceiling too tight for its real
workload. config/expansion.yaml now gives it its own per-entry timeout
override; every other tool in the same bucket keeps the shared default.
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

    assert by_tool.get("domain_hunter") == 100
    # Its single-source bucket-mates keep the original, tighter default.
    for tool in ("crt_sh_query", "whois_lookup", "dnsenum_scan"):
        assert by_tool.get(tool) == 60, f"{tool} timeout unexpectedly changed: {by_tool.get(tool)}"
