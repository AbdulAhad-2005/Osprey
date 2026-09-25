"""operator_memory.py — the disclosed Plan 03 gap, closed: link_assets/
link_assets_many/record_think used to construct a Finding directly with a
caller-asserted confidence, bypassing confidence_for (Plan 03's one law).
record_think now routes through hypothesis_store (Plan 05's actual object
for "operator thinking"); link_assets/link_assets_many no longer mint a
Finding at all — the graph edge itself is the durable write.
"""

from __future__ import annotations

import uuid

from osprey.services import hypothesis_store, operator_memory


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def test_link_assets_creates_edge_and_no_finding():
    eid = _eid()
    result = operator_memory.link_assets(
        engagement_id=eid, source="host:a.test", target="host:b.test",
        relation="shares_auth_cookie", evidence="same Set-Cookie domain observed", confidence="likely",
    )
    assert result["source_id"] and result["target_id"]
    assert "finding_id" not in result


def test_link_assets_requires_evidence():
    import pytest

    with pytest.raises(ValueError, match="evidence"):
        operator_memory.link_assets(
            engagement_id=_eid(), source="host:a.test", target="host:b.test",
            relation="same_app_as", evidence="",
        )


def test_link_assets_many_creates_edges_and_no_finding():
    eid = _eid()
    result = operator_memory.link_assets_many(
        engagement_id=eid, source="host:seed.test", relation="resolves_to",
        targets=["ip:1.2.3.4", "ip:1.2.3.5"], evidence="dns A records observed",
    )
    assert result["count"] == 2
    assert "finding_id" not in result


def test_record_think_creates_a_hypothesis_not_a_finding():
    eid = _eid()
    result = operator_memory.record_think(
        engagement_id=eid, hypothesis="admin panel may share session with portal",
        plan="compare cookies", evidence="same cookie domain",
    )
    assert "hypothesis_id" in result
    assert "finding_id" not in result

    stored = hypothesis_store.list_for_engagement(eid)
    assert len(stored) == 1
    assert "admin panel may share session with portal" in stored[0].statement
    assert "Plan: compare cookies" in stored[0].statement


def test_record_think_requires_hypothesis_text():
    import pytest

    with pytest.raises(ValueError, match="hypothesis"):
        operator_memory.record_think(engagement_id=_eid(), hypothesis="")
