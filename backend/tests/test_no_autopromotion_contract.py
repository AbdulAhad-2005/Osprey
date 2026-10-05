"""Plan 19 Phase 1 — the no-false-positive ruler (the second core motive).

The scar this pins down: a raw scanner signal (a single nuclei/nikto match) is
mechanically turned into a VULNERABILITY *finding* by ``promote_observations``,
with no brain ever judging it — the exact path that manufactures false positives
and walks the LLM to fake conclusions (plan 19 §1b, 19a).

  * CHARACTERIZATION (passes today): promotion manufactures a finding from a bare
    scanner signal.
  * CONTRACT (xfail strict → red when fixed): a scanner signal NEVER becomes a
    finding without a brain authoring it. Turns green at Phase 6, when
    ``promote_observations`` and the PROMOTE_OBSERVATIONS capability are deleted.

``_findings_from_auto_promotion`` is written to survive that deletion: once the
promotion path is gone the import fails and it returns [] — so the contract
xpasses (strict → fails loudly: "un-xfail me") and the characterization fails
("delete me"). Both flip exactly when the launderer dies.
"""
from __future__ import annotations

import uuid

from osprey.schemas.engagement import EngagementCreateRequest
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.engagement_store import get_engagement_store
from osprey.services.observation_store import get_observation_store


def _engagement_with_scanner_signal() -> str:
    """Scratch engagement holding one SCANNER_SIGNAL observation — the shape a
    nuclei/nikto parser emits (a claimed-severity match), with NO corroboration
    and NO brain judgment attached."""
    store = get_engagement_store()
    eng = store.create(EngagementCreateRequest(target=f"fp-{uuid.uuid4().hex[:8]}.invalid", name="fp-ruler"))
    get_observation_store().record(
        Observation(
            engagement_id=eng.id,
            type=ObservationType.SCANNER_SIGNAL,
            source_tool="nuclei_scan",
            target=eng.target,
            details={
                "title": "Exposed .git directory [medium]",
                "claimed_severity": "medium",
                "template_id": "exposed-git",
            },
            tags=["nuclei", "claimed_severity:medium"],
        )
    )
    return eng.id


def _no_auto_promotion_path_exists() -> bool:
    """promote_observations was deleted in Phase 6 — importing it must fail. If a
    future change reintroduces any no-brain promotion function, this flips and the
    guarantee below fails loudly."""
    try:
        from osprey.services.finding_pipeline import promote_observations  # noqa: F401
    except ImportError:
        return False
    return True


def test_deterministic_engine_never_offers_auto_promotion():
    """PERMANENT GUARANTEE (plan 19 Phase 2/6 slice): the deterministic engine's
    opportunity set must never include a promote_observations capability. The
    former PROMOTE_OBSERVATIONS capability auto-ran promotion with no human — it
    is removed from the engine, so a scanner signal present in state yields recon/
    analysis opportunities but NEVER an auto-finding step."""
    from osprey.services.engagement_graph import get_engagement_graph
    from osprey.schemas.engagement_graph import AssetType
    from osprey.services import investigation_capabilities

    eid = _engagement_with_scanner_signal()
    try:
        # A root subject must exist for the analytical block to run at all —
        # ensure a domain node so the test proves the capability is gone, not
        # merely that the block was skipped.
        get_engagement_graph().ensure_node(
            engagement_id=eid, asset_type=AssetType.DOMAIN,
            label=get_engagement_store().get(eid).target,
        )
        step = investigation_capabilities.list_step(eid)
        capabilities = {str(getattr(o, "capability", "")) for o in step.opportunities}
        assert not any("promote" in c.lower() for c in capabilities), (
            f"deterministic engine still offers auto-promotion: {capabilities}"
        )
    finally:
        get_engagement_store().delete(eid)


def test_no_no_brain_promotion_path_exists():
    """PERMANENT GUARANTEE (plan 19 Phase 6): there is no function that turns a
    scanner signal into a finding without a brain. promote_observations — the
    "truth from corroboration-count" launderer — is deleted. A scanner claim
    stays a scanner_claim observation; only file_finding (a brain citing evidence)
    creates a conclusion."""
    assert _no_auto_promotion_path_exists() is False
