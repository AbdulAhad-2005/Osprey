"""Tests for the operator-profile service (the human operator's preferences).

Filesystem paths are redirected to a tmp dir so the real profile is never touched.
"""

from __future__ import annotations

import pytest
from osprey.services import operator_profile as op


@pytest.fixture(autouse=True)
def _tmp_profile(monkeypatch, tmp_path):
    monkeypatch.setattr(op, "_PROFILE_DIR", tmp_path)
    monkeypatch.setattr(op, "_PROFILE_PATH", tmp_path / "profile.md")
    monkeypatch.setattr(op, "_PENDING_DIR", tmp_path / ".pending")


def test_empty_profile():
    assert op.get_profile() == ""
    assert op.profile_for_context() == ""
    assert op.list_pending() == []


def test_propose_then_approve_flow():
    rec = op.propose_preference(preference="prefer concise output", rationale="user asked twice")
    assert rec["status"] == "proposed"
    pending = op.list_pending()
    assert len(pending) == 1 and pending[0]["preference"] == "prefer concise output"
    # Not in the confirmed profile until approved.
    assert op.get_profile() == ""

    op.approve_preference(rec["id"])
    assert "prefer concise output" in op.get_profile()
    assert op.list_pending() == []  # promoted, no longer pending


def test_reject_removes_pending_without_confirming():
    rec = op.propose_preference(preference="always run nuclei first")
    assert op.reject_preference(rec["id"]) is True
    assert op.list_pending() == []
    assert op.get_profile() == ""
    assert op.reject_preference(rec["id"]) is False  # already gone


def test_add_direct_and_dedup():
    op.add_preference("report findings in CVSS")
    assert "report findings in CVSS" in op.get_profile()
    dup = op.add_preference("report findings in CVSS")
    assert dup["status"] == "duplicate"
    # Only one line for it.
    assert op.get_profile().count("report findings in CVSS") == 1


def test_profile_for_context_returns_only_pref_lines():
    op.add_preference("prefer concise output")
    op.add_preference("avoid brute force without asking")
    ctx = op.profile_for_context()
    assert "- prefer concise output" in ctx
    assert "- avoid brute force without asking" in ctx
    assert "# Operator profile" not in ctx  # header stripped for the compact form


def test_validation_rejects_bad_length():
    with pytest.raises(op.OperatorProfileError):
        op.propose_preference(preference="x")  # too short
    with pytest.raises(op.OperatorProfileError):
        op.propose_preference(preference="y" * 501)  # too long
