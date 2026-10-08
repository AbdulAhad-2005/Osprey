"""B5.2 — two concurrent engagements on one backend never cross-write. The
backend takes an explicit engagement_id on every stateful op (no ambient
"current" session), so interleaved writes to two engagements stay isolated."""

from __future__ import annotations

from osprey.schemas.finding import FindingType
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.finding_pipeline import file_finding
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store


def _engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        return client.post("/api/v1/engagements/", json={"target": target}).json()["id"]


def _file(eid: str, target: str, title: str) -> None:
    obs = get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target=target, source_tool="nuclei_scan",
    ))
    file_finding(engagement_id=eid, title=title, finding_type=FindingType.VULNERABILITY, observation_ids=[obs.id])


def test_two_engagements_do_not_cross_write_even_interleaved():
    eid_a = _engagement("isolation-a.test")
    eid_b = _engagement("isolation-b.test")
    assert eid_a != eid_b

    # Interleave writes to A and B.
    _file(eid_a, "isolation-a.test", "finding A1")
    _file(eid_b, "isolation-b.test", "finding B1")
    _file(eid_a, "isolation-a.test", "finding A2")

    store = get_findings_store()
    titles_a = {f.title for f in store.list(engagement_id=eid_a, limit=100)}
    titles_b = {f.title for f in store.list(engagement_id=eid_b, limit=100)}

    assert "finding A1" in titles_a and "finding A2" in titles_a
    assert "finding B1" in titles_b
    # No leakage across the boundary.
    assert not (titles_a & titles_b)
    assert "finding B1" not in titles_a
    assert "finding A1" not in titles_b
