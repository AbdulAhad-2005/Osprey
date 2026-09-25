"""Evidence + Observation layer — plans/harness/02-evidence-and-observation-layer.md
Steps 1-2. Covers: evidence recording/observed-flag, observation dedup-by-signature
merge (the required "high-volume data" control), and the type/target/engagement
list paths downstream readers (Plan 03, world model) will use.
"""

from __future__ import annotations

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.evidence_store import get_evidence_store
from osprey.services.observation_store import get_observation_store


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_evidence_record_and_mark_observed():
    eid = _make_engagement("evidence-store.test")
    store = get_evidence_store()

    ev = store.record(
        engagement_id=eid,
        tool_name="whois_lookup",
        target="evidence-store.test",
        command="whois evidence-store.test",
        stdout_path="/tmp/pentest/x/whois.stdout.txt",
        exit_code=0,
        duration_ms=1200,
    )
    assert ev is not None
    assert ev.observed is False

    fetched = store.get(ev.id)
    assert fetched is not None
    assert fetched.tool_name == "whois_lookup"

    store.mark_observed(ev.id)
    assert store.get(ev.id).observed is True

    unobserved = store.list_for_engagement(eid, unobserved_only=True)
    assert ev.id not in {e.id for e in unobserved}


def test_evidence_without_engagement_id_returns_none():
    assert get_evidence_store().record(engagement_id="", tool_name="whois_lookup") is None


def test_observation_dedup_merges_on_signature_not_duplicate_rows():
    eid = _make_engagement("obs-dedup.test")
    store = get_observation_store()

    first = Observation(
        engagement_id=eid,
        type=ObservationType.SERVICE,
        target="obs-dedup.test",
        source_tool="nmap_service_scan",
        details={"port": 443, "service": "nginx", "version": "1.24"},
    )
    result1 = store.record_many([first])
    assert result1.stored == 1
    assert result1.merged == 0

    # A re-scan (different run_id/evidence_id) of the exact same fact must
    # merge, not duplicate — this is Plan 02's required volume control.
    second = Observation(
        engagement_id=eid,
        type=ObservationType.SERVICE,
        target="obs-dedup.test",
        source_tool="nmap_service_scan",
        details={"port": 443, "service": "nginx", "version": "1.24"},
        evidence_id="deadbeef0001",  # a real evidence_id is uuid4().hex[:12] — column is String(12)
    )
    result2 = store.record_many([second])
    assert result2.stored == 0
    assert result2.merged == 1
    assert result2.observations[0].id == result1.observations[0].id
    assert result2.observations[0].occurrence_count == 2

    all_obs = store.list_for_engagement(eid)
    assert len(all_obs) == 1


def test_observation_distinct_details_do_not_merge():
    eid = _make_engagement("obs-distinct.test")
    store = get_observation_store()

    a = Observation(
        engagement_id=eid,
        type=ObservationType.PORT,
        target="obs-distinct.test",
        details={"port": 80},
    )
    b = Observation(
        engagement_id=eid,
        type=ObservationType.PORT,
        target="obs-distinct.test",
        details={"port": 443},
    )
    result = store.record_many([a, b])
    assert result.stored == 2
    assert result.merged == 0
    assert len(store.list_for_engagement(eid)) == 2


def test_observation_dict_key_order_does_not_affect_signature():
    eid = _make_engagement("obs-order.test")
    store = get_observation_store()

    a = Observation(
        engagement_id=eid,
        type=ObservationType.SERVICE,
        target="obs-order.test",
        details={"port": 22, "service": "ssh"},
    )
    b = Observation(
        engagement_id=eid,
        type=ObservationType.SERVICE,
        target="obs-order.test",
        details={"service": "ssh", "port": 22},
    )
    result = store.record_many([a, b])
    assert result.stored == 1
    assert result.merged == 1


def test_list_by_type_and_by_target():
    eid = _make_engagement("obs-filter.test")
    store = get_observation_store()

    store.record_many(
        [
            Observation(
                engagement_id=eid,
                type=ObservationType.PORT,
                target="obs-filter.test",
                details={"port": 22},
            ),
            Observation(
                engagement_id=eid,
                type=ObservationType.TECHNOLOGY,
                target="obs-filter.test",
                details={"technology": "nginx"},
            ),
            Observation(
                engagement_id=eid,
                type=ObservationType.PORT,
                target="other-host.test",
                details={"port": 80},
            ),
        ]
    )

    by_type = store.list_by_type(eid, ObservationType.PORT)
    assert len(by_type) == 2

    by_target = store.list_by_target(eid, "obs-filter.test")
    assert len(by_target) == 2
    assert {o.type for o in by_target} == {ObservationType.PORT, ObservationType.TECHNOLOGY}


def test_record_without_engagement_id_raises():
    import pytest

    with pytest.raises(ValueError):
        get_observation_store().record(Observation(type=ObservationType.PORT))
