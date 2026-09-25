"""plans/harness/05-world-model-and-attack-paths.md done criterion: an
AttackPath can be proposed spanning >=3 observations across different
categories and advanced to a validated finding; attack_path_coverage becomes
computable via the Scorecard.
"""

from __future__ import annotations

import uuid

from osprey.schemas.attack_path import AttackPathStatus, AttackPathStep, AttackPathStepKind
from osprey.schemas.observation import Observation, ObservationType
from osprey.services import attack_path_store
from osprey.services.observation_store import get_observation_store


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def test_multi_step_chain_spanning_three_categories_advances_to_validated():
    eid = _eid()
    store = get_observation_store()

    # public API endpoint (URL) -> internal endpoint reference (INJECTION_POINT)
    # -> object identifier in a different authz boundary (SCANNER_SIGNAL) ->
    # cross-user access (hypothesis -> validated finding). Three distinct
    # observation categories, exactly the chain shape the plan's own example
    # describes.
    api_obs = store.record(Observation(
        engagement_id=eid, type=ObservationType.URL, target="api.chain-test.internal",
        source_tool="httpx_probe", details={"url": "https://api.chain-test.internal/v1/users"},
    ))
    param_obs = store.record(Observation(
        engagement_id=eid, type=ObservationType.INJECTION_POINT, target="https://api.chain-test.internal/v1/users",
        source_tool="arjun_scan", details={"parameter": "internal_ref"},
    ))
    signal_obs = store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="api.chain-test.internal",
        source_tool="nuclei_scan", details={"title": "object identifier crosses authz boundary"},
    ))

    path = attack_path_store.propose(
        eid, title="public API -> internal ref -> cross-user access",
        steps=[
            AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id=api_obs.id, rationale="public API endpoint discovered"),
        ],
    )
    path = attack_path_store.advance(
        path.id, status=AttackPathStatus.INVESTIGATING,
        append_step=AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id=param_obs.id, rationale="internal endpoint reference parameter"),
    )
    path = attack_path_store.advance(
        path.id,
        append_step=AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id=signal_obs.id, rationale="different authz boundary object identifier"),
    )
    assert len(path.steps) == 3
    assert {s.ref_id for s in path.steps} == {api_obs.id, param_obs.id, signal_obs.id}

    # A controlled PoC reproduces the chain -> file a finding -> validate the path.
    validated = attack_path_store.advance(path.id, status=AttackPathStatus.VALIDATED, finding_id="finding-abc123")
    assert validated.status == AttackPathStatus.VALIDATED
    assert validated.finding_id == "finding-abc123"

    active_paths = attack_path_store.list_for_engagement(eid)
    assert len(active_paths) == 1
    assert active_paths[0].status == AttackPathStatus.VALIDATED


def test_attack_path_coverage_metric_counts_paths_on_scratch_engagement():
    from osprey.schemas.benchmark import Recording, ReplayResult
    from osprey.services.benchmark.scoring import score

    eid = _eid()
    attack_path_store.propose(
        eid, title="chain", steps=[AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id="obs1")],
    )
    replay = ReplayResult(fixture_name="chain-fixture", scratch_engagement_id=eid, calls_replayed=1)
    recording = Recording(name="chain-fixture", calls=[])
    scorecard = score(replay, recording)
    assert scorecard.attack_path_coverage == 1
