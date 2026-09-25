"""Ground a claimed "reproduction" evidence_detail against real tool output —
plans/harness/12-deterministic-evidence-verification.md Step 1.

``platform_file_finding``'s ``evidence_kind="reproduction"`` used to accept
whatever free text a caller wrote, with no check it was grounded in anything
real — the platform's highest-trust confidence tier (CONFIRMED,
services/confidence.py) minted on nothing but an LLM's own say-so. This is
the deterministic check: does the claimed detail actually contain text that
shows up in real, already-recorded tool output for the cited observation?

Matches where the field has converged (researched fresh, not re-derived):
XBOW's stated differentiator is "LLMs do creative exploration, deterministic
code does strict verification"; "Forgeable Confirmation: Deterministic Rules
vs AI Judges" (arXiv 2609.24200) measured AI judges breaking at a median of
50% attacker-controlled content vs. 2% for deterministic checks that read
evidence the claim itself can't have written. Scaled to what Osprey already
records at tool-execution time (``Evidence.raw_excerpt``,
``Observation.details``) — nothing new to capture, just a check that was
never run against it.
"""

from __future__ import annotations

import re

from osprey.schemas.observation import Observation
from osprey.services.evidence_store import get_evidence_store

# Below this, a claim is too short/generic to ground meaningfully ("it
# worked", "vulnerable") — reject outright rather than let a trivial common
# substring pass.
_MIN_MATCH_LEN = 20
_MAX_CLAIM_LEN = 4000

_WS_RE = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _WS_RE.sub(" ", (text or "")).strip().lower()


def _raw_text_candidates(observation: Observation) -> list[str]:
    """Every already-recorded raw-text source for this observation — none of
    them writable by the evidence_detail claim itself."""
    candidates: list[str] = []
    if observation.evidence_id:
        evidence = get_evidence_store().get(observation.evidence_id)
        if evidence is not None and evidence.raw_excerpt:
            candidates.append(evidence.raw_excerpt)
    # Parsers routinely stash a raw excerpt directly on the observation too
    # (summary_agent.py's RAW fallback, several typed parsers) — check those
    # keys as a second, independent source, in case evidence_id wasn't set.
    for key in ("snippet", "evidence", "raw", "body", "response", "output"):
        value = observation.details.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value)
    return candidates


def _shares_substring(claim: str, raw: str, min_len: int) -> bool:
    """True when some contiguous run of ``min_len`` chars in ``claim``
    appears verbatim in ``raw``. A claim genuinely quoting real output will
    have that quoted window land inside the real text; a fabricated claim
    won't, no matter how plausible-sounding."""
    if len(claim) < min_len or len(raw) < min_len:
        return False
    for i in range(0, len(claim) - min_len + 1):
        if claim[i : i + min_len] in raw:
            return True
    return False


def ground_reproduction_claim(detail: str, observation: Observation) -> tuple[bool, str]:
    """(True, "") when ``detail`` contains a genuine excerpt of real,
    already-recorded tool output for ``observation`` — (False, reason)
    otherwise. Deliberately conservative: a false reject just asks the
    caller to quote something real or use evidence_kind='attestation'
    instead; a false accept would mint CONFIRMED on nothing.
    """
    claim = _normalize(detail)[:_MAX_CLAIM_LEN]
    if len(claim) < _MIN_MATCH_LEN:
        return False, (
            f"evidence_detail is too short/generic ({len(claim)} chars after normalizing) to "
            f"ground a reproduction claim — quote at least {_MIN_MATCH_LEN} characters actually "
            "seen in the tool's real output."
        )

    raw_candidates = [c for c in (_normalize(t) for t in _raw_text_candidates(observation)) if c]
    if not raw_candidates:
        return False, (
            f"observation {observation.id} has no recorded raw tool output to ground a "
            "reproduction claim against (no evidence_id/raw_excerpt, no details snippet) — use "
            "evidence_kind='attestation' if you're vouching without a machine-checkable artifact."
        )

    for raw in raw_candidates:
        if _shares_substring(claim, raw, _MIN_MATCH_LEN):
            return True, ""
    return False, (
        "evidence_detail doesn't contain any excerpt found in this observation's real recorded "
        "output — quote the actual tool output that shows the reproduction, or use "
        "evidence_kind='attestation' if you're vouching without a machine-checkable artifact."
    )
