"""Replay & benchmark harness — CLI/CI entry point's backend
(plans/harness/01-replay-benchmark-harness.md Step 5). A dev/measurement
surface, not a pentest capability — no MCP tool wraps this on purpose.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from osprey.schemas.benchmark import FixtureLabels, Recording, Scorecard
from osprey.services.benchmark.fixtures import install_builtin_fixtures, load_labels
from osprey.services.benchmark.recorder import (
    RECORDINGS_DIR,
    list_recordings,
    load_recording,
    record_engagement,
    save_recording,
)
from osprey.services.benchmark.replay import replay_recording
from osprey.services.benchmark.scoring import score

router = APIRouter()

# Scorecards are written to disk (not just kept in-process) — `diff` is a
# stated CI entry point (Step 5), and CI runners typically don't share one
# long-lived backend process between `run` and `diff` invocations.
_RESULTS_DIR = RECORDINGS_DIR.parent / "results"


def _save_result(scorecard: Scorecard) -> None:
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (_RESULTS_DIR / f"{scorecard.run_id}.json").write_text(
        scorecard.model_dump_json(indent=2), encoding="utf-8"
    )


def _load_result(run_id: str) -> Scorecard | None:
    path = _RESULTS_DIR / f"{run_id}.json"
    if not path.is_file():
        return None
    return Scorecard.model_validate_json(path.read_text(encoding="utf-8"))


@router.get("/fixtures", summary="List available fixtures")
def list_fixtures() -> dict:
    return {"fixtures": list_recordings()}


@router.post("/fixtures/install-builtin", summary="Write the built-in synthetic fixtures to disk")
def install_builtin() -> dict:
    return {"installed": install_builtin_fixtures()}


@router.post("/record", summary="Record a live/recent engagement as a fixture")
async def record(body: dict) -> dict:
    engagement_id = str(body.get("engagement_id") or "").strip()
    name = str(body.get("name") or "").strip()
    if not engagement_id or not name:
        raise HTTPException(400, detail="engagement_id and name are required")
    recording = await record_engagement(
        engagement_id, name=name, target=str(body.get("target") or "")
    )
    path = save_recording(recording)
    degraded = sum(1 for c in recording.calls if c.stdout_source in ("snippet", "none"))
    return {
        "name": recording.name,
        "path": str(path),
        "calls_recorded": len(recording.calls),
        "degraded_fidelity_calls": degraded,
    }


@router.post("/run", response_model=Scorecard, summary="Replay a fixture and score it")
async def run(body: dict) -> Scorecard:
    fixture = str(body.get("fixture") or "").strip()
    if not fixture:
        raise HTTPException(400, detail="fixture is required")
    try:
        recording: Recording = load_recording(fixture)
    except FileNotFoundError as exc:
        raise HTTPException(404, detail=str(exc)) from exc

    labels: FixtureLabels | None = load_labels(fixture)
    replay_result = await replay_recording(recording)
    scorecard = score(replay_result, recording, labels=labels)
    _save_result(scorecard)
    return scorecard


@router.get("/results/{run_id}", response_model=Scorecard, summary="Fetch a past scorecard by run_id")
def get_result(run_id: str) -> Scorecard:
    result = _load_result(run_id)
    if result is None:
        raise HTTPException(404, detail=f"No benchmark run '{run_id}' on disk")
    return result


@router.get("/diff", summary="Diff two scorecards by run_id")
def diff(
    baseline: str = Query(...),
    candidate: str = Query(...),
) -> dict:
    base = _load_result(baseline)
    cand = _load_result(candidate)
    if base is None or cand is None:
        missing = baseline if base is None else candidate
        raise HTTPException(404, detail=f"No benchmark run '{missing}' on disk")
    numeric_fields = [
        "false_positive_rate",
        "validated_finding_count",
        "confirmed_without_proof_count",
        "attack_surface_coverage",
        "redundant_action_count",
        "missed_known_vuln_count",
    ]
    deltas = {}
    for field in numeric_fields:
        b, c = getattr(base, field), getattr(cand, field)
        deltas[field] = {"baseline": b, "candidate": c, "delta": (c - b) if (b is not None and c is not None) else None}
    return {"baseline_run_id": baseline, "candidate_run_id": candidate, "deltas": deltas}
