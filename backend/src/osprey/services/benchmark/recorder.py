"""Capture a live/recent engagement's tool calls as a portable, replayable
fixture — passive: reads what's already stored, never re-runs a tool.

Ground truth for *what ran, in what order* is the audit log
(``get_audit_log().query``). Full-fidelity stdout only exists inside the Kali
container's ``/tmp/pentest/<engagement_id>/`` — reachable only via a live
``docker exec`` while Kali is up (``artifacts.read_artifact_slice``). So
recording is meant to happen soon after (or during) the engagement it
captures, while that connection and the in-process audit log are still live —
not as a retroactive operation over an old, possibly-restarted backend.

Both the audit log and the stdout index are in-memory/process-lifetime only
today (their own modules say so). Recording degrades honestly rather than
silently: every ``ToolCallRecord`` carries ``stdout_source`` so replay/scoring
never mistakes a 400-char snippet for the real thing.
"""

from __future__ import annotations

import logging
from pathlib import Path

from osprey.schemas.benchmark import Recording, ToolCallRecord
from osprey.services.audit_log import get_audit_log
from osprey.services.stdout_index import list_stdout_index

logger = logging.getLogger(__name__)

RECORDINGS_DIR = Path(__file__).resolve().parents[5] / "benchmarks" / "recordings"


def _match_stdout_entries(
    audit_entries: list, index_entries: list[dict]
) -> dict[int, dict]:
    """Greedy nearest-by-timestamp match of each audit entry to a stdout_index
    entry with the same tool_name — both logs are appended, in call order, by
    the same ``tool_execution.py`` call (index first, then audit), so this is
    reliable without either log carrying a shared call id."""
    remaining = sorted(index_entries, key=lambda e: e.get("ts") or 0)
    matched: dict[int, dict] = {}
    for i, entry in enumerate(audit_entries):
        tool = entry.action.tool_name
        audit_ts = entry.timestamp.timestamp()
        best_idx, best_delta = None, None
        for j, cand in enumerate(remaining):
            if cand.get("tool") != tool:
                continue
            delta = abs((cand.get("ts") or 0) - audit_ts)
            if best_delta is None or delta < best_delta:
                best_idx, best_delta = j, delta
        if best_idx is not None:
            matched[i] = remaining.pop(best_idx)
    return matched


async def record_engagement(
    engagement_id: str,
    *,
    name: str,
    target: str = "",
    max_calls: int = 200,
) -> Recording:
    """Build a Recording from the current (in-process) audit log + stdout
    index for ``engagement_id``, pulling full stdout live from Kali when
    reachable. Never executes a tool; purely reads existing state."""
    audit_entries = get_audit_log().query(engagement_id=engagement_id, limit=max_calls)
    index = list_stdout_index(engagement_id, limit=max_calls).get("entries") or []
    matches = _match_stdout_entries(audit_entries, index)

    calls: list[ToolCallRecord] = []
    for i, entry in enumerate(audit_entries):
        action = entry.action
        idx_entry = matches.get(i)
        stdout = ""
        stdout_source: str = "none"

        if idx_entry and idx_entry.get("stdout_path"):
            try:
                from osprey.services.artifacts import read_artifact_slice

                slice_ = await read_artifact_slice(
                    engagement_id, idx_entry["stdout_path"], offset=0, limit=500_000
                )
                if slice_.get("ok"):
                    stdout = slice_.get("content") or ""
                    stdout_source = "artifact"
            except Exception as exc:  # noqa: BLE001 — Kali unreachable, degrade
                logger.debug("recorder: live artifact read failed for %s: %s", action.tool_name, exc)

        if not stdout and idx_entry and idx_entry.get("snippet"):
            stdout = idx_entry["snippet"]
            stdout_source = "snippet"

        if not stdout:
            # Last resort: any finding this tool produced may carry a raw_data
            # blob (see summary_agent.py's force_raw_observation path) — only
            # present when the tool had no/weak structured parse, but durable.
            try:
                from osprey.services.findings_store import get_findings_store

                for f in get_findings_store().list(
                    engagement_id=engagement_id, run_id=None, limit=50
                ):
                    if f.source_tool == action.tool_name and getattr(f, "raw_data", ""):
                        stdout = f.raw_data
                        stdout_source = "finding_raw_data"
                        break
            except Exception as exc:  # noqa: BLE001
                logger.debug("recorder: raw_data fallback failed: %s", exc)

        calls.append(
            ToolCallRecord(
                tool_name=action.tool_name,
                target=action.target,
                command=action.command,
                stdout=stdout,
                returncode=action.returncode,
                success=action.success,
                duration_seconds=action.duration_seconds,
                timestamp=entry.timestamp,
                stdout_source=stdout_source,  # type: ignore[arg-type]
            )
        )
        if stdout_source in ("snippet", "none"):
            logger.warning(
                "recorder: %s recorded with degraded fidelity (%s) — Kali artifact "
                "unreachable; replay will see less output than the real run had.",
                action.tool_name, stdout_source,
            )

    return Recording(
        name=name,
        source_engagement_id=engagement_id,
        target=target,
        synthetic=False,
        calls=calls,
    )


def save_recording(recording: Recording, *, directory: Path | None = None) -> Path:
    """Write a Recording as one JSONL line per call, plus a header line. Never
    overwrites silently — caller decides on a name collision."""
    out_dir = directory or RECORDINGS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{recording.name}.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        header = recording.model_copy(update={"calls": []})
        fh.write(header.model_dump_json() + "\n")
        for call in recording.calls:
            fh.write(call.model_dump_json() + "\n")
    return path


def load_recording(name: str, *, directory: Path | None = None) -> Recording:
    in_dir = directory or RECORDINGS_DIR
    path = in_dir / f"{name}.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"No recording named '{name}' at {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError(f"Empty recording file: {path}")
    header = Recording.model_validate_json(lines[0])
    calls = [ToolCallRecord.model_validate_json(line) for line in lines[1:] if line.strip()]
    return header.model_copy(update={"calls": calls})


def list_recordings(*, directory: Path | None = None) -> list[str]:
    in_dir = directory or RECORDINGS_DIR
    if not in_dir.is_dir():
        return []
    return sorted(p.stem for p in in_dir.glob("*.jsonl"))
