"""Operator profile — the human operator's durable preferences / working style.

This is the third memory tier, distinct from the other two:
  * engagement memory  → facts about the TARGET (findings, graph)
  * learned skills      → reusable TECHNIQUES, target-agnostic
  * operator profile    → the HUMAN operator (verbosity, preferred tools, risk
                          tolerance, reporting style, recurring choices)

It is what makes the harness "adapt to each user": the confirmed profile is fed
into every engagement's context, so any driver — the native CLI or an external
MCP harness — sees it and adapts. Writes are consent-gated (Hermes-style): the
LLM may PROPOSE a preference it inferred from how the operator works, but a
proposal is inert until the operator approves it. Operator-local and git-ignored
— never shipped, committed, or sent anywhere.

Preferences deliberately do NOT live in the learned-skills library: a skill is a
technique applied to a target; a preference is a fact about the person. Mixing
them would pollute the technique index the phase methodology pulls from. Same
consent machinery, separate store.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_PROFILE_DIR = _PROJECT_ROOT / "skills" / "operator"     # git-ignored
_PROFILE_PATH = _PROFILE_DIR / "profile.md"              # confirmed preferences
_PENDING_DIR = _PROFILE_DIR / ".pending"                 # LLM proposals awaiting approval

_MIN_PREF, _MAX_PREF = 3, 500
# Keep the confirmed profile small — it rides in every context read.
_MAX_PROFILE_CHARS = 8_000
_HEADER = (
    "# Operator profile\n\n"
    "Confirmed preferences for how this operator works — the harness adapts to these.\n\n"
)


class OperatorProfileError(ValueError):
    """A preference failed validation."""


def get_profile() -> str:
    """The confirmed profile markdown (empty string if none yet)."""
    try:
        return _PROFILE_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def profile_for_context(*, max_chars: int = 2_000) -> str:
    """Compact confirmed profile for injection into a context read. Returns just
    the preference lines (no header), truncated — this sits in every packet, so
    it must stay small. Empty when there is no profile."""
    prof = get_profile()
    if not prof:
        return ""
    lines = [ln.strip() for ln in prof.splitlines() if ln.strip().startswith("-")]
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[:max_chars].rsplit("\n", 1)[0] + "\n- …(more in operator profile)"
    return text


def _validate(preference: str) -> str:
    pref = " ".join((preference or "").split())
    if not (_MIN_PREF <= len(pref) <= _MAX_PREF):
        raise OperatorProfileError(f"preference must be {_MIN_PREF}-{_MAX_PREF} chars (got {len(pref)}).")
    return pref


def _proposal_path(pid: str) -> Path:
    return _PENDING_DIR / f"{(pid or '').strip()}.json"


def propose_preference(
    *, preference: str, rationale: str = "", engagement_id: str = ""
) -> dict[str, Any]:
    """Store an LLM-inferred preference proposal. Inert until the operator
    approves it. Raises OperatorProfileError on a malformed preference."""
    pref = _validate(preference)
    _PENDING_DIR.mkdir(parents=True, exist_ok=True)
    pid = uuid.uuid4().hex[:12]
    rec = {
        "id": pid,
        "preference": pref,
        "rationale": (rationale or "").strip()[:500],
        "engagement_id": engagement_id,
        "status": "proposed",
        "created_at": time.time(),
    }
    _proposal_path(pid).write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return rec


def list_pending() -> list[dict[str, Any]]:
    if not _PENDING_DIR.exists():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(_PENDING_DIR.glob("*.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, ValueError):
            continue
    return sorted(out, key=lambda d: d.get("created_at", 0), reverse=True)


def get_pending(pid: str) -> dict[str, Any] | None:
    path = _proposal_path(pid)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        return None


def reject_preference(pid: str) -> bool:
    path = _proposal_path(pid)
    if not path.exists():
        return False
    path.unlink()
    return True


def approve_preference(pid: str) -> dict[str, Any]:
    """Promote a pending proposal into the confirmed profile."""
    rec = get_pending(pid)
    if rec is None:
        raise OperatorProfileError(f"no pending preference with id '{pid}'.")
    res = _append_confirmed(rec["preference"])
    _proposal_path(pid).unlink(missing_ok=True)
    return res


def add_preference(preference: str) -> dict[str, Any]:
    """Operator-direct add — the operator is author and approver, so no proposal
    step. Same validation + de-duplication as the approval path."""
    return _append_confirmed(_validate(preference))


def _append_confirmed(preference: str) -> dict[str, Any]:
    """Append one confirmed preference line, de-duplicating exact repeats and
    enforcing the size cap (oldest lines drop first if the cap is exceeded)."""
    _PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    entry = preference if preference.startswith("- ") else f"- {preference}"
    existing = get_profile()
    lines = [ln.rstrip() for ln in existing.splitlines()]
    pref_lines = [ln for ln in lines if ln.strip().startswith("-")]
    if entry in pref_lines:
        return {"status": "duplicate", "preference": preference}
    pref_lines.append(entry)
    body = _HEADER + "\n".join(pref_lines) + "\n"
    if len(body) > _MAX_PROFILE_CHARS:
        # Drop oldest preference lines until it fits.
        while pref_lines and len(_HEADER + "\n".join(pref_lines) + "\n") > _MAX_PROFILE_CHARS:
            pref_lines.pop(0)
        body = _HEADER + "\n".join(pref_lines) + "\n"
    _PROFILE_PATH.write_text(body, encoding="utf-8")
    return {"status": "added", "preference": preference, "total": len(pref_lines)}
