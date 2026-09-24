"""Replay & benchmark harness schemas (plans/harness/01-replay-benchmark-harness.md).

The ruler the harness program measures itself against: a recorded engagement
becomes a portable fixture; replaying a fixture re-feeds its tool outputs
through the *current* ingestion pipeline (no live tools, no live LLM by
default) and scores what came out.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


class LLMCallRecord(BaseModel):
    """One LLM request/response captured during ingestion for a tool call.

    Empty today (nothing in the current pipeline calls an LLM during
    ingestion in a way this hook is wired to yet, aside from
    ``observation_engine``'s structural-extraction pass); the field exists so
    recordings taken after Plan 02/03 land are replayable in `deterministic`
    mode (feeding back this recorded response) without re-recording anything.
    """

    purpose: str  # e.g. "observation_extraction", "file_finding", "dynamic_structuring"
    request_summary: str = ""
    response: dict[str, Any] = Field(default_factory=dict)


class ToolCallRecord(BaseModel):
    """One recorded tool execution — enough to replay it without running the
    real tool again."""

    tool_name: str
    target: str = ""
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    success: bool = False
    timed_out: bool = False
    duration_seconds: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # How `stdout` was obtained — full-fidelity capture from the live Kali
    # artifact vs. a bounded fallback. Replay/scoring must know this: a
    # snippet-sourced record under-represents what the real parser would see.
    stdout_source: Literal["artifact", "snippet", "finding_raw_data", "none"] = "none"
    llm_calls: list[LLMCallRecord] = Field(default_factory=list)


class Recording(BaseModel):
    """A whole engagement's tool-call sequence, portable as one JSONL file."""

    name: str
    source_engagement_id: str = ""
    target: str = ""
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    synthetic: bool = False
    calls: list[ToolCallRecord] = Field(default_factory=list)


class NoiseLabel(BaseModel):
    """A known-not-real signal a synthetic fixture plants on purpose — e.g. an
    endpoint that returns 501 and should never become a finding.

    Matched by ``title_contains`` (finding-granular), not by tool/target —
    every finding from one tool call usually shares the same target, so a
    target-only match would flag every finding from that call as noise
    instead of the one specific signal being tested."""

    tool_name: str
    title_contains: str
    reason: str = ""


class PlantedVuln(BaseModel):
    """A known-real vulnerability a synthetic fixture plants on purpose, for
    computing `missed_known_vuln_count` against ground truth."""

    tool_name: str
    target: str
    title_contains: str
    description: str = ""


class FixtureLabels(BaseModel):
    """Ground truth for a fixture — only meaningful for synthetic fixtures
    (a real recording has no planted ground truth to check against)."""

    fixture_name: str
    noise: list[NoiseLabel] = Field(default_factory=list)
    planted_vulns: list[PlantedVuln] = Field(default_factory=list)


class ReplayResult(BaseModel):
    """What the current pipeline produced when a recording was replayed
    against a fresh scratch engagement."""

    fixture_name: str
    scratch_engagement_id: str
    findings: list[dict[str, Any]] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)
    calls_replayed: int = 0
    live_llm: bool = False
    replayed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Scorecard(BaseModel):
    """The benchmark's output — one run's numbers, each metric labeled so a
    diff never silently compares LLM noise against a deterministic run."""

    run_id: str
    fixture_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    mode: Literal["deterministic", "live-llm"] = "deterministic"

    # Deterministic metrics — reproducible bit-for-bit given the same fixture
    # and pipeline version.
    false_positive_rate: float | None = None
    validated_finding_count: int = 0
    confirmed_without_proof_count: int = 0
    attack_surface_coverage: int = 0
    redundant_action_count: int = 0
    missed_known_vuln_count: int | None = None
    # plans/harness/05-world-model-and-attack-paths.md: active + validated
    # attack paths for the replayed scratch engagement. 0 on every fixture
    # that plants no multi-step chain (the current built-ins) — that's
    # expected, not a gap; a fixture built for this metric drives it.
    attack_path_coverage: int = 0

    # llm-dependent — only populated in --live-llm mode; None in the default
    # deterministic run (there is nothing to measure without an LLM in the loop).
    time_to_first_validated_finding_seconds: float | None = None

    notes: list[str] = Field(default_factory=list)

    @property
    def metric_modes(self) -> dict[str, str]:
        """Which metrics are deterministic vs. llm-dependent — read by the
        CLI/CI renderer so a scorecard is never silently misread as one
        single-precision number when part of it is a distribution."""
        return {
            "false_positive_rate": "deterministic",
            "validated_finding_count": "deterministic",
            "confirmed_without_proof_count": "deterministic",
            "attack_surface_coverage": "deterministic",
            "redundant_action_count": "deterministic",
            "missed_known_vuln_count": "deterministic",
            "attack_path_coverage": "deterministic",
            "time_to_first_validated_finding_seconds": "llm-dependent",
        }
