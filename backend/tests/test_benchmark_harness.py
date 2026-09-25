"""Replay & benchmark harness — plans/harness/01-replay-benchmark-harness.md.

Covers: the recorder against real audit_log/stdout_index state (proving the
"at least one recorded fixture" mechanism, not just hand-authored synthetic
ones), the replay driver's determinism (no live LLM by default), and scoring.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from osprey.main import app
from osprey.schemas.audit import AuditAction
from osprey.schemas.benchmark import FixtureLabels, NoiseLabel, PlantedVuln
from osprey.services.audit_log import get_audit_log
from osprey.services.benchmark import fixtures as fixtures_mod
from osprey.services.benchmark.recorder import (
    load_recording,
    record_engagement,
    save_recording,
)
from osprey.services.benchmark.replay import replay_recording
from osprey.services.benchmark.scoring import score
from osprey.services.stdout_index import record_stdout_entry


def _make_engagement(target: str) -> str:
    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


# --------------------------------------------------------------------------
# Recorder — against real (simulated-live) audit_log + stdout_index state
# --------------------------------------------------------------------------

def test_record_engagement_reconstructs_a_real_call(tmp_path):
    """Proves the recorder mechanism itself: seed the same two in-process
    stores tool_execution.py writes to on a real run, then record — this is
    the "at least one recorded fixture" done-criterion, exercised without
    needing a live Kali container."""
    eid = _make_engagement("recorder-proof.test")

    get_audit_log().record(
        AuditAction(
            tool_name="whois_lookup",
            target="recorder-proof.test",
            engagement_id=eid,
            command="whois recorder-proof.test",
            success=True,
            returncode=0,
            duration_seconds=1.2,
        )
    )
    record_stdout_entry(
        engagement_id=eid,
        tool_name="whois_lookup",
        target="recorder-proof.test",
        stdout_path="/tmp/pentest/does-not-exist.stdout.txt",  # no live Kali — snippet fallback
        snippet="Domain Name: RECORDER-PROOF.TEST\nRegistrar: Example Registrar\n",
        bytes_hint=64,
        success=True,
    )

    recording = asyncio.run(record_engagement(eid, name="recorder-proof", target="recorder-proof.test"))

    assert len(recording.calls) == 1
    call = recording.calls[0]
    assert call.tool_name == "whois_lookup"
    assert call.target == "recorder-proof.test"
    assert call.success is True
    # No live Kali in this environment -> the artifact read fails and the
    # recorder must degrade honestly to the snippet, not silently drop it.
    assert call.stdout_source == "snippet"
    assert "RECORDER-PROOF.TEST" in call.stdout


def test_saved_recording_round_trips_and_replays(tmp_path):
    eid = _make_engagement("recorder-roundtrip.test")
    get_audit_log().record(
        AuditAction(
            tool_name="whois_lookup",
            target="recorder-roundtrip.test",
            engagement_id=eid,
            command="whois recorder-roundtrip.test",
            success=True,
        )
    )
    record_stdout_entry(
        engagement_id=eid,
        tool_name="whois_lookup",
        target="recorder-roundtrip.test",
        snippet="Domain Name: RECORDER-ROUNDTRIP.TEST\n",
        success=True,
    )

    recording = asyncio.run(
        record_engagement(eid, name="recorder-roundtrip", target="recorder-roundtrip.test")
    )
    path = save_recording(recording, directory=tmp_path)
    assert path.is_file()

    reloaded = load_recording("recorder-roundtrip", directory=tmp_path)
    assert reloaded.name == recording.name
    assert len(reloaded.calls) == 1
    assert reloaded.calls[0].tool_name == "whois_lookup"

    result = asyncio.run(replay_recording(reloaded))
    assert result.calls_replayed == 1
    assert result.live_llm is False


# --------------------------------------------------------------------------
# Replay determinism — no live LLM by default
# --------------------------------------------------------------------------

def test_replay_is_deterministic_by_default_no_llm_fallback():
    """A tool with no registered parser (script:*) would otherwise trigger
    observation_engine's LLM structural extraction — replay must disable that
    so the result never depends on whether the replaying process has an LLM
    key. No Finding is ever created on this path (Plan 02)."""
    from osprey.schemas.benchmark import Recording, ToolCallRecord

    recording = Recording(
        name="determinism-proof",
        target="determinism.test",
        synthetic=True,
        calls=[
            ToolCallRecord(
                tool_name="script:probe",
                target="determinism.test",
                stdout="some unstructured text an LLM might try to restructure\n",
                success=True,
                stdout_source="none",
            )
        ],
    )
    result = asyncio.run(replay_recording(recording))
    assert result.findings == []
    # Deterministic mode: only the raw-observation fallback should appear —
    # never LLM-paraphrased observations with invented structure.
    assert len(result.observations) == 1
    assert result.observations[0]["type"] == "raw"
    assert "some unstructured text" in result.observations[0]["details"]["snippet"]


# --------------------------------------------------------------------------
# Built-in synthetic fixtures — end to end through the real parsers
# --------------------------------------------------------------------------

def test_builtin_web_recon_mixed_fixture_no_longer_mints_the_501_false_positive(tmp_path):
    """Baseline (Plan 01, pre-fix): this fixture's bare 501 line was promoted
    to a CONFIRMED finding with zero corroboration —
    false_positive_rate > 0, confirmed_without_proof_count >= 1 (see
    benchmarks/results/baseline-synthetic-web-recon-mixed.json). Since
    Plan 02+03, the tool-execution path creates Observations, not Findings —
    the 501 line becomes an http_response/url Observation, never a finding,
    so both metrics read 0. This is the fix working, not a gap: the planted
    CVE is still recoverable (as a SCANNER_SIGNAL observation), so nothing
    was silently dropped either."""
    fixtures_mod.install_builtin_fixtures(directory=tmp_path)
    recording = load_recording("synthetic-web-recon-mixed", directory=tmp_path)
    labels = fixtures_mod.load_labels("synthetic-web-recon-mixed", directory=tmp_path)
    assert labels is not None

    result = asyncio.run(replay_recording(recording))
    scorecard = score(result, recording, labels=labels)

    assert result.findings == []
    assert scorecard.false_positive_rate == 0.0
    assert scorecard.confirmed_without_proof_count == 0
    assert scorecard.validated_finding_count == 0
    # The genuinely planted CVE must still be recoverable from what the
    # parsers *did* produce — not swept away along with the fixed bug.
    assert scorecard.missed_known_vuln_count == 0
    assert any("CVE-2016-6210" in str(o.get("details", {})) for o in result.observations)


def test_builtin_repeat_scan_fixture_measures_redundancy(tmp_path):
    fixtures_mod.install_builtin_fixtures(directory=tmp_path)
    recording = load_recording("synthetic-repeat-scan-redundancy", directory=tmp_path)
    labels = fixtures_mod.load_labels("synthetic-repeat-scan-redundancy", directory=tmp_path)

    result = asyncio.run(replay_recording(recording))
    scorecard = score(result, recording, labels=labels)
    assert scorecard.redundant_action_count == 2  # 3 identical calls, 2 redundant


# --------------------------------------------------------------------------
# Scoring — unit-level, no replay needed
# --------------------------------------------------------------------------

def test_noise_label_matches_by_title_not_bare_target():
    """Regression test for the exact bug this suite caught during
    development: matching noise on (tool, target) alone flags every finding
    from that call, not just the specific noisy one."""
    from osprey.schemas.benchmark import Recording, ReplayResult

    findings = [
        {"source_tool": "script:probe", "target": "host.test", "title": "real vuln",
         "description": "", "confidence": "confirmed"},
        {"source_tool": "script:probe", "target": "host.test", "title": "noisy endpoint 501",
         "description": "", "confidence": "confirmed"},
    ]
    replay = ReplayResult(
        fixture_name="unit-test", scratch_engagement_id="x", findings=findings, calls_replayed=1
    )
    recording = Recording(name="unit-test", calls=[])
    labels = FixtureLabels(
        fixture_name="unit-test",
        noise=[NoiseLabel(tool_name="script:probe", title_contains="noisy endpoint")],
    )
    scorecard = score(replay, recording, labels=labels)
    assert scorecard.false_positive_rate == 0.5  # exactly 1 of 2, not both
    assert scorecard.confirmed_without_proof_count == 1


def test_missed_known_vuln_count_when_planted_vuln_absent():
    from osprey.schemas.benchmark import Recording, ReplayResult

    replay = ReplayResult(
        fixture_name="unit-test-2", scratch_engagement_id="x", findings=[], calls_replayed=1
    )
    recording = Recording(name="unit-test-2", calls=[])
    labels = FixtureLabels(
        fixture_name="unit-test-2",
        planted_vulns=[PlantedVuln(tool_name="x", target="y", title_contains="CVE-9999-0001")],
    )
    scorecard = score(replay, recording, labels=labels)
    assert scorecard.missed_known_vuln_count == 1
