"""Finding re-verification — re-run the tool(s) behind a finding's evidence
and check whether the signal still reproduces.

The gap this closes: ``confidence_for`` (services/confidence.py) computes
confidence once, from whatever evidence exists at filing time, and never
revisits it. A finding filed CONFIRMED hours (or days) into a long
engagement — via a real REPRODUCTION, or an operator/LLM ATTESTATION — is
reported as CONFIRMED forever after, even if the target's since been patched,
the WAF now blocks it, or the original "reproduction" was a misfire. Strix/
HexStrike/Pentest-Swarm-AI survey: only Pentest-Swarm-AI has an equivalent
(``ConfirmationAgent`` — re-executes a finding's reproduction and can demote
it). Adapted here, not copied: evidence is append-only everywhere else in
this codebase (Plan 03's one law), so this NEVER edits or deletes a past
confirming record — it only appends a RECHECK_FAILED record when the signal
doesn't reproduce, which ``confidence_for`` already knows how to weigh
(recency-aware: CONFIRMED → LIKELY only when the recheck is the MOST RECENT
relevant evidence; a later successful re-verification clears it).

Only findings with a re-runnable observation (a real source_tool, not
``operator_record``/``script:``/``shell:``) are candidates — an
ATTESTATION-only finding with no underlying tool observation has nothing to
mechanically re-run; it stays exactly what the one law already says it is.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from osprey.schemas.finding import EvidenceRecord, EvidenceRecordKind, RecheckReason
from osprey.schemas.observation import observation_signature
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store

logger = logging.getLogger(__name__)

# Sources with nothing mechanical to re-run — an operator/LLM conclusion or
# ad-hoc shell/script output, not a catalog tool with a stable re-invocation.
_NOT_REVERIFIABLE_PREFIXES = ("operator_record", "script:", "shell:")


def _is_reverifiable_source(source_tool: str) -> bool:
    name = (source_tool or "").strip()
    if not name:
        return False
    return not any(name == p or name.startswith(p) for p in _NOT_REVERIFIABLE_PREFIXES)


async def reverify_finding(finding_id: str, *, run_id: str = "") -> dict[str, Any]:
    """Re-run the tool(s) behind this finding's observations; append a
    RECHECK_FAILED evidence record for each one that no longer reproduces.
    Never blocks on a finding with nothing re-runnable — reports that
    plainly instead of guessing.
    """
    findings_store = get_findings_store()
    finding = findings_store.get(finding_id)
    if finding is None:
        return {"error": f"no finding with id '{finding_id}'"}

    obs_store = get_observation_store()
    observations = [o for o in (obs_store.get(oid) for oid in finding.observation_ids) if o is not None]
    candidates = [o for o in observations if _is_reverifiable_source(o.source_tool)]
    if not candidates:
        return {
            "finding_id": finding_id,
            "checked": 0,
            "reproduced": 0,
            "failed": 0,
            "confidence": finding.confidence.value,
            "note": (
                "Nothing re-runnable — every cited observation is operator/LLM-"
                "sourced or ad-hoc shell/script output, not a catalog tool with a "
                "stable re-invocation. Confidence already reflects its real evidence."
            ),
        }

    from osprey.schemas.tools import ToolExecutionRequest
    from osprey.services.tool_execution import execute_tool_request

    reproduced = 0
    failed = 0
    checked_tools: list[str] = []
    now = datetime.now(timezone.utc)

    for obs in candidates:
        before_signature = observation_signature(obs)
        before_last_seen = obs.last_seen_at
        checked_tools.append(obs.source_tool)
        try:
            response = await execute_tool_request(
                ToolExecutionRequest(
                    tool_name=obs.source_tool,
                    params={"target": obs.target},
                    engagement_id=finding.engagement_id,
                    run_id=run_id or finding.run_id,
                    record_findings=True,
                    force_refresh=True,  # a cache hit would prove nothing about NOW
                )
            )
        except Exception as exc:  # noqa: BLE001
            # The tool couldn't run — inconclusive, learns nothing about the target.
            logger.info("reverify_finding: %s failed for finding %s (non-fatal): %s", obs.source_tool, finding_id, exc)
            failed += 1
            findings_store.append_evidence(
                finding_id,
                EvidenceRecord(
                    kind=EvidenceRecordKind.RECHECK_FAILED,
                    source_tool=obs.source_tool,
                    observation_id=obs.id,
                    reason=RecheckReason.INCONCLUSIVE.value,
                    detail=f"Re-run could not complete: {str(exc)[:200]}",
                ),
            )
            continue

        if not getattr(response, "success", False):
            # Tool ran but errored/returned nothing (e.g. target unreachable) —
            # also inconclusive, not evidence the issue is gone.
            failed += 1
            findings_store.append_evidence(
                finding_id,
                EvidenceRecord(
                    kind=EvidenceRecordKind.RECHECK_FAILED,
                    source_tool=obs.source_tool,
                    observation_id=obs.id,
                    reason=RecheckReason.INCONCLUSIVE.value,
                    detail=f"Re-ran {obs.source_tool} against {obs.target} but it did not complete cleanly.",
                ),
            )
            continue

        refreshed = obs_store.get(obs.id)
        # observation_store bumps last_seen_at on the SAME signature re-appearing.
        same_signature_seen_again = (
            refreshed is not None
            and observation_signature(refreshed) == before_signature
            and refreshed.last_seen_at is not None
            and (before_last_seen is None or refreshed.last_seen_at > before_last_seen)
        )
        if same_signature_seen_again:
            reproduced += 1
        else:
            # Tool ran clean and the signal is gone — actively not reproduced.
            failed += 1
            findings_store.append_evidence(
                finding_id,
                EvidenceRecord(
                    kind=EvidenceRecordKind.RECHECK_FAILED,
                    source_tool=obs.source_tool,
                    observation_id=obs.id,
                    reason=RecheckReason.NOT_REPRODUCED.value,
                    detail=f"Re-ran {obs.source_tool} against {obs.target} — the original signal did not reappear.",
                ),
            )

    final = findings_store.get(finding_id)
    return {
        "finding_id": finding_id,
        "checked": len(candidates),
        "checked_tools": checked_tools,
        "reproduced": reproduced,
        "failed": failed,
        "confidence_before": finding.confidence.value,
        "confidence_after": final.confidence.value if final else finding.confidence.value,
        "checked_at": now.isoformat(),
    }
