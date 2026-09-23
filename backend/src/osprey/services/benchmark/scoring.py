"""Score a ReplayResult against optional ground truth — the metrics named in
plans/harness/01-replay-benchmark-harness.md Step 3.

Since plans/harness/02-evidence-and-observation-layer.md +
03-earned-finding-pipeline.md, the tool-execution path creates Observations,
not Findings — ``findings`` on a fresh replay is legitimately empty (nothing
promotes an observation to a finding yet outside ``platform_file_finding`` /
``promote_observations``, neither of which a recorded tool call drives).
``false_positive_rate`` / ``confirmed_without_proof_count`` /
``validated_finding_count`` are computed over findings and so read 0/None
until Plan 03's promotion path runs — that is the fix working, not a gap.
``missed_known_vuln_count`` checks observations too, since a planted vuln's
signal (a SCANNER_SIGNAL, a CVE-bearing technology match, …) is exactly what
Plan 02's parsers still surface — losing track of it here would make the
benchmark blind during the exact transition it exists to measure.

Every metric here is deterministic today (no LLM in the current ingestion
path outside `observation_engine`'s structural extraction, which no fixture
exercises yet). `time_to_first_validated_finding_seconds` stays None until
`--live-llm` mode exists — a "0" or a guess would be a fabricated number, not
a metric.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter

from osprey.schemas.benchmark import FixtureLabels, Recording, ReplayResult, Scorecard


def _matches_planted_vuln_observation(o: dict, pv) -> bool:
    if o.get("source_tool", "") != pv.tool_name:
        return False
    needle = pv.title_contains.lower()
    blob = json.dumps(o.get("details") or {}, default=str) + " " + " ".join(o.get("tags") or [])
    return needle in blob.lower()


def score(
    replay: ReplayResult,
    recording: Recording,
    *,
    labels: FixtureLabels | None = None,
) -> Scorecard:
    findings = replay.findings
    observations = replay.observations
    notes: list[str] = []

    def _matches_noise(f: dict, label) -> bool:
        if f.get("source_tool", "") != label.tool_name:
            return False
        needle = label.title_contains.lower()
        return needle in f"{f.get('title', '')} {f.get('description', '')}".lower()

    # --- false_positive_rate: findings matching a planted noise label -------
    fp_count = 0
    if labels and labels.noise:
        for f in findings:
            if any(_matches_noise(f, label) for label in labels.noise):
                fp_count += 1
        fp_rate: float | None = (fp_count / len(findings)) if findings else 0.0
    else:
        fp_rate = None
        notes.append("false_positive_rate: no noise labels on this fixture — unmeasured, not zero.")

    # --- confirmed_without_proof_count: CONFIRMED findings that are noise ---
    # Pre-Plan-03 there is no formal "proof" record to check (that's exactly
    # what Plan 03 adds), so this is approximated as: findings the pipeline
    # graded CONFIRMED that a labeled fixture says are actually noise — the
    # concrete, measurable form of the "single observation = confirmed" bug
    # this whole program exists to kill. Recomputed honestly once Plan 03
    # lands (a real evidence-less CONFIRMED becomes directly detectable).
    confirmed_without_proof = 0
    if labels and labels.noise:
        for f in findings:
            if f.get("confidence") == "confirmed" and any(_matches_noise(f, label) for label in labels.noise):
                confirmed_without_proof += 1

    # --- validated_finding_count: CONFIRMED findings today -------------------
    validated_count = sum(1 for f in findings if f.get("confidence") == "confirmed")

    # --- attack_surface_coverage: distinct non-empty targets reached --------
    coverage = len({f.get("target") for f in findings if f.get("target")})

    # --- redundant_action_count: same (tool, target) recorded more than once
    call_keys = Counter((c.tool_name, c.target) for c in recording.calls)
    redundant = sum(count - 1 for count in call_keys.values() if count > 1)

    # --- missed_known_vuln_count: planted vulns with no matching finding OR
    # observation. A finding match would mean Plan 03's promotion path ran;
    # an observation match is what Plan 02's parsers alone still guarantee —
    # either counts as "not missed", since nothing was silently dropped.
    missed: int | None = None
    if labels and labels.planted_vulns:
        missed = 0
        titles_and_desc = [
            f"{f.get('title', '')} {f.get('description', '')}".lower() for f in findings
        ]
        for pv in labels.planted_vulns:
            needle = pv.title_contains.lower()
            found_in_findings = any(needle in blob for blob in titles_and_desc)
            found_in_observations = any(_matches_planted_vuln_observation(o, pv) for o in observations)
            if not found_in_findings and not found_in_observations:
                missed += 1

    # --- attack_path_coverage: active/validated attack paths on the
    # replayed scratch engagement (plans/harness/05-world-model-and-attack-
    # paths.md). Deterministic replay never proposes one itself (that's a
    # reasoner action — Plan 09) — 0 here means "no chain proposed", not
    # "the mechanism is broken"; a fixture built to exercise it would
    # pre-seed paths against the scratch engagement before scoring.
    attack_path_coverage = 0
    if replay.scratch_engagement_id:
        from osprey.services import attack_path_store

        attack_path_coverage = len(attack_path_store.list_for_engagement(replay.scratch_engagement_id))

    return Scorecard(
        run_id=uuid.uuid4().hex[:12],
        fixture_name=replay.fixture_name,
        mode="live-llm" if replay.live_llm else "deterministic",
        false_positive_rate=fp_rate,
        validated_finding_count=validated_count,
        confirmed_without_proof_count=confirmed_without_proof,
        attack_surface_coverage=coverage,
        redundant_action_count=redundant,
        missed_known_vuln_count=missed,
        attack_path_coverage=attack_path_coverage,
        time_to_first_validated_finding_seconds=None,
        notes=notes,
    )
