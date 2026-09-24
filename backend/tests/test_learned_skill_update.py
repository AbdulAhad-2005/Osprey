"""Tests for the learned-skill UPDATE path (refine an existing learned skill).

Filesystem/index bits are monkeypatched so the logic — reject unknown target,
skip the novelty/duplicate gate on a real update, and carry the update flag into
the proposal — is tested without touching the real skills tree.
"""

from __future__ import annotations

import pytest
from osprey.services import learned_skills as ls

_DESC = "When facing X, do Y to achieve Z on the target host."  # 20-300 chars
_BODY = "## Technique\n\n" + ("Step details that make this a real, reusable methodology. " * 6)


def _no_learned(monkeypatch):
    monkeypatch.setattr(ls, "list_learned", lambda: [])


def _one_learned(monkeypatch, slug="waf-origin-bypass"):
    monkeypatch.setattr(
        ls, "list_learned",
        lambda: [{"name": slug, "path": f"learned/{slug}.md", "description": _DESC, "phases": ["recon"]}],
    )


def test_update_existing_unknown_slug_rejected(monkeypatch, tmp_path):
    _no_learned(monkeypatch)
    monkeypatch.setattr(ls, "_PROPOSALS_DIR", tmp_path)
    with pytest.raises(ls.LearnedSkillError):
        ls.propose_skill(
            name="waf-origin-bypass", phase="recon", description=_DESC, content=_BODY,
            update_existing="does-not-exist",
        )


def test_update_existing_skips_dedup_and_records_flag(monkeypatch, tmp_path):
    _one_learned(monkeypatch, "waf-origin-bypass")
    monkeypatch.setattr(ls, "_PROPOSALS_DIR", tmp_path)
    # These guards must NOT run on an update (an update is meant to resemble the
    # skill it refines) — make them explode so the test fails if they're called.
    def _boom(*a, **k):
        raise AssertionError("dedup/identity guard must be skipped on update")
    monkeypatch.setattr(ls, "_reject_if_exact_duplicate", _boom)
    monkeypatch.setattr(ls, "_reject_if_identity_conflict", _boom)

    prop = ls.propose_skill(
        name="waf origin bypass (v2)", phase="recon", description=_DESC, content=_BODY,
        update_existing="waf-origin-bypass",
    )
    assert prop["update_existing"] == "waf-origin-bypass"
    # slug is forced to the target so approval overwrites it in place.
    assert prop["slug"] == "waf-origin-bypass"
    assert prop["similar_to"] == []


def test_new_skill_still_runs_the_guards(monkeypatch, tmp_path):
    _no_learned(monkeypatch)
    monkeypatch.setattr(ls, "_PROPOSALS_DIR", tmp_path)
    called = {"exact": False, "identity": False}
    monkeypatch.setattr(ls, "_reject_if_exact_duplicate", lambda *a, **k: called.__setitem__("exact", True))
    monkeypatch.setattr(ls, "_reject_if_identity_conflict", lambda *a, **k: called.__setitem__("identity", True))
    monkeypatch.setattr(ls, "_similarity_flags", lambda *a, **k: [])
    ls.propose_skill(name="brand-new-technique", phase="recon", description=_DESC, content=_BODY)
    assert called == {"exact": True, "identity": True}


def test_is_learned_skill(monkeypatch):
    _one_learned(monkeypatch, "my-skill")
    assert ls.is_learned_skill("my-skill") is True
    assert ls.is_learned_skill("My Skill") is True  # slugified
    assert ls.is_learned_skill("unknown") is False
