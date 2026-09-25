"""attack_path_store / question_store / hypothesis_store — plans/harness/
05-world-model-and-attack-paths.md Steps 3-5.
"""

from __future__ import annotations

import uuid

import pytest

from osprey.schemas.attack_path import AttackPathStatus, AttackPathStep, AttackPathStepKind
from osprey.schemas.reasoning import HypothesisStatus, QuestionStatus
from osprey.services import attack_path_store, hypothesis_store, question_store


def _eid() -> str:
    return uuid.uuid4().hex[:12]


# --------------------------------------------------------------------------
# attack_path_store
# --------------------------------------------------------------------------

def test_propose_requires_title_and_steps():
    eid = _eid()
    with pytest.raises(ValueError):
        attack_path_store.propose(eid, title="", steps=[])
    with pytest.raises(ValueError):
        attack_path_store.propose(eid, title="X", steps=[])


def test_propose_and_get_round_trip():
    eid = _eid()
    step = AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id="obs1", rationale="public API found")
    path = attack_path_store.propose(eid, title="public API -> internal ref", steps=[step])
    assert path.status == AttackPathStatus.HYPOTHESIZED
    fetched = attack_path_store.get(path.id)
    assert fetched is not None
    assert fetched.title == "public API -> internal ref"
    assert len(fetched.steps) == 1


def test_advance_appends_step_and_changes_status():
    eid = _eid()
    path = attack_path_store.propose(
        eid, title="chain",
        steps=[AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id="obs1")],
    )
    updated = attack_path_store.advance(
        path.id,
        status=AttackPathStatus.INVESTIGATING,
        append_step=AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id="obs2", rationale="cross-boundary ref"),
    )
    assert updated is not None
    assert updated.status == AttackPathStatus.INVESTIGATING
    assert len(updated.steps) == 2
    assert updated.steps[1].ref_id == "obs2"


def test_attach_evidence_appends_observation_step():
    eid = _eid()
    path = attack_path_store.propose(
        eid, title="chain", steps=[AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id="obs1")],
    )
    updated = attack_path_store.attach_evidence(path.id, observation_id="obs2", rationale="new hop")
    assert updated is not None
    assert len(updated.steps) == 2
    assert updated.steps[-1].kind == AttackPathStepKind.OBSERVATION


def test_advance_can_validate_with_finding_id():
    eid = _eid()
    path = attack_path_store.propose(
        eid, title="chain", steps=[AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id="obs1")],
    )
    updated = attack_path_store.advance(path.id, status=AttackPathStatus.VALIDATED, finding_id="f123")
    assert updated.status == AttackPathStatus.VALIDATED
    assert updated.finding_id == "f123"


def test_list_active_excludes_validated_and_dead():
    eid = _eid()
    active = attack_path_store.propose(
        eid, title="active", steps=[AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id="obs1")],
    )
    dead = attack_path_store.propose(
        eid, title="dead", steps=[AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id="obs2")],
    )
    attack_path_store.advance(dead.id, status=AttackPathStatus.DEAD)

    active_ids = {p.id for p in attack_path_store.list_active(eid)}
    assert active.id in active_ids
    assert dead.id not in active_ids


def test_advance_unknown_id_returns_none():
    assert attack_path_store.advance("does-not-exist", status=AttackPathStatus.DEAD) is None


# --------------------------------------------------------------------------
# question_store
# --------------------------------------------------------------------------

def test_raise_question_requires_text():
    eid = _eid()
    with pytest.raises(ValueError):
        question_store.raise_question(eid, text="")


def test_raise_and_answer_question():
    eid = _eid()
    q = question_store.raise_question(eid, text="Why does this host share an IP with another?")
    assert q.status == QuestionStatus.OPEN
    answered = question_store.answer(q.id, answer_text="Shared hosting provider.")
    assert answered.status == QuestionStatus.ANSWERED
    assert answered.answer == "Shared hosting provider."


def test_dismiss_question():
    eid = _eid()
    q = question_store.raise_question(eid, text="Irrelevant question")
    dismissed = question_store.dismiss(q.id)
    assert dismissed.status == QuestionStatus.DISMISSED


def test_list_open_excludes_answered_and_dismissed():
    eid = _eid()
    open_q = question_store.raise_question(eid, text="still open")
    answered_q = question_store.raise_question(eid, text="will answer")
    question_store.answer(answered_q.id, answer_text="done")

    open_ids = {q.id for q in question_store.list_open(eid)}
    assert open_q.id in open_ids
    assert answered_q.id not in open_ids


# --------------------------------------------------------------------------
# hypothesis_store
# --------------------------------------------------------------------------

def test_raise_hypothesis_requires_statement():
    eid = _eid()
    with pytest.raises(ValueError):
        hypothesis_store.raise_hypothesis(eid, statement="")


def test_raise_hypothesis_and_add_evidence_both_directions():
    eid = _eid()
    h = hypothesis_store.raise_hypothesis(eid, statement="Origin IP is exposed behind CDN")
    assert h.status == HypothesisStatus.ACTIVE

    supported = hypothesis_store.add_evidence(h.id, observation_id="obs-support", supports=True)
    assert supported.supporting_observation_ids == ["obs-support"]

    contradicted = hypothesis_store.add_evidence(h.id, observation_id="obs-contra", supports=False)
    assert contradicted.contradicting_observation_ids == ["obs-contra"]
    # Supporting evidence from before is preserved.
    assert contradicted.supporting_observation_ids == ["obs-support"]


def test_add_evidence_does_not_duplicate_same_observation():
    eid = _eid()
    h = hypothesis_store.raise_hypothesis(eid, statement="X")
    hypothesis_store.add_evidence(h.id, observation_id="obs1", supports=True)
    updated = hypothesis_store.add_evidence(h.id, observation_id="obs1", supports=True)
    assert updated.supporting_observation_ids == ["obs1"]


def test_resolve_rejects_active_status():
    eid = _eid()
    h = hypothesis_store.raise_hypothesis(eid, statement="X")
    with pytest.raises(ValueError):
        hypothesis_store.resolve(h.id, status=HypothesisStatus.ACTIVE)


def test_resolve_confirmed_and_refuted():
    eid = _eid()
    h1 = hypothesis_store.raise_hypothesis(eid, statement="X")
    confirmed = hypothesis_store.resolve(h1.id, status=HypothesisStatus.CONFIRMED)
    assert confirmed.status == HypothesisStatus.CONFIRMED

    h2 = hypothesis_store.raise_hypothesis(eid, statement="Y")
    refuted = hypothesis_store.resolve(h2.id, status=HypothesisStatus.REFUTED)
    assert refuted.status == HypothesisStatus.REFUTED


def test_list_active_excludes_resolved():
    eid = _eid()
    active = hypothesis_store.raise_hypothesis(eid, statement="still active")
    resolved = hypothesis_store.raise_hypothesis(eid, statement="resolved")
    hypothesis_store.resolve(resolved.id, status=HypothesisStatus.CONFIRMED)

    active_ids = {h.id for h in hypothesis_store.list_active(eid)}
    assert active.id in active_ids
    assert resolved.id not in active_ids
