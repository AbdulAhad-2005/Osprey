"""Plan 19 — the report/dossier keeps facts, scanner claims, and conclusions
visibly separate and never dresses a scanner claim up as a finding.

With no brain in the loop (no-LLM run), a scanner match must appear under
``scanner_claims`` (verified=False), technology/infrastructure must still be
populated from observations+graph, and ``findings_by_severity`` (conclusions)
must be empty — the honest dossier the deterministic floor produces.
"""
from __future__ import annotations

from osprey.schemas.engagement import EngagementCreateRequest
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.engagement_store import get_engagement_store
from osprey.services.observation_store import get_observation_store
from osprey.services.report_generator import build_report_data


def _engagement_with_scanner_and_tech() -> str:
    store = get_engagement_store()
    eng = store.create(EngagementCreateRequest(target="report-honest.test", name="report-honest"))
    obs = get_observation_store()
    obs.record(Observation(
        engagement_id=eng.id, type=ObservationType.SCANNER_SIGNAL, source_tool="nuclei_scan",
        target="report-honest.test",
        details={"title": "Exposed .git [medium]", "claimed_severity": "medium", "template_id": "exposed-git"},
        tags=["nuclei", "claimed_severity:medium"],
    ))
    obs.record(Observation(
        engagement_id=eng.id, type=ObservationType.TECHNOLOGY, source_tool="httpx_probe",
        target="report-honest.test", details={"technology": "nginx,WordPress"},
    ))
    return eng.id


def test_scanner_match_is_a_claim_not_a_finding():
    eid = _engagement_with_scanner_and_tech()
    try:
        data = build_report_data(eid)
        claims = data["scanner_claims"]
        assert any(c["template_id"] == "exposed-git" for c in claims)
        assert all(c["verified"] is False for c in claims)
        assert all("scanner_claimed_severity" in c for c in claims)
        # No brain authored anything → zero conclusions, honestly.
        assert data["findings_by_severity"] == []
        assert data["metrics"]["total_conclusions"] == 0
        assert data["metrics"]["total_scanner_claims"] == 1
    finally:
        get_engagement_store().delete(eid)


def test_technology_comes_from_observations_not_findings():
    eid = _engagement_with_scanner_and_tech()
    try:
        data = build_report_data(eid)
        techs = set(data["technologies_detected"])
        # httpx packs a comma-separated group; the report splits it into parts.
        assert "nginx" in techs and "WordPress" in techs
    finally:
        get_engagement_store().delete(eid)
