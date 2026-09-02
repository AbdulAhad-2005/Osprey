"""Single adaptation pipeline for every agent and phase."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from osprey.platform.failure_analysis import FailureContext, format_failure_analysis
from osprey.platform.hint_providers import HintContext, collect_hints
from osprey.platform.orchestration_hints import build_orchestration_meta, format_orchestration_hints
from osprey.platform.run_context import RunAssistState, note_failure, note_tool_outcome, repeat_failure_warning
from osprey.platform.situational_context import build_situational_brief
from osprey.schemas.tools import ToolExecutionResponse
from osprey.services.findings_store import get_findings_store
from osprey.services.parsers.registry import digest_tool_output, ensure_parsers_loaded

logger = logging.getLogger(__name__)

ensure_parsers_loaded()

_SMB_TOOLS = frozenset(
    {"enum4linux_scan", "enum4linux_ng_advanced", "smbmap_scan", "netexec_scan", "nbtscan_netbios"}
)


@dataclass
class AdaptationContext:
    tool_response: ToolExecutionResponse
    assist_state: RunAssistState
    signature: str
    engagement_id: str
    run_id: str
    target: str
    run_phase: str
    params: dict[str, Any]
    user_goal: str = ""


def format_findings_snapshot(
    *,
    engagement_id: str,
    run_id: str,
    max_chars: int = 800,
) -> str:
    text = get_findings_store().structured_summary_for_agent(
        engagement_id=engagement_id,
        run_id=run_id,
    )
    if not text or text.startswith("No findings"):
        return ""
    if len(text) <= max_chars:
        return f"SESSION FINDINGS:\n{text}"
    return f"SESSION FINDINGS:\n{text[:max_chars]}\n[... findings truncated]"


def _infer_skip_category(response: ToolExecutionResponse) -> str | None:
    if response.tool_name not in _SMB_TOOLS or response.success:
        return None
    blob = f"{response.stdout}\n{response.stderr}\n{response.error}".lower()
    if any(
        phrase in blob
        for phrase in (
            "connection refused",
            "do not exist",
            "cannot obtain",
            "session setup failed",
            "no workgroup",
        )
    ):
        return "smb"
    return None


def enrich_tool_result(
    base_text: str,
    ctx: AdaptationContext,
) -> str:
    """Augment raw tool output with digests, hints, orchestration, and memory."""
    parts = [base_text]
    response = ctx.tool_response

    useful_output = response.success and bool((response.stdout or "").strip())

    note_tool_outcome(
        tool_name=response.tool_name,
        success=useful_output,
        state=ctx.assist_state,
        skip_category=_infer_skip_category(response),
    )

    if useful_output:
        digest = digest_tool_output(response.tool_name, response.stdout)
        if digest:
            parts.append(f"PARSED SUMMARY:\n{digest}")

    repeat = repeat_failure_warning(signature=ctx.signature, state=ctx.assist_state)
    if repeat:
        parts.append(repeat)

    if not response.success:
        failure_ctx = FailureContext(
            tool_name=response.tool_name,
            command=response.command or "",
            stdout=response.stdout or "",
            stderr=response.stderr or "",
            error=response.error or "",
            returncode=response.returncode,
            timed_out=response.timed_out,
            params=ctx.params,
        )
        analysis = format_failure_analysis(failure_ctx)
        if analysis:
            parts.append(analysis)

        hint_ctx = HintContext(
            tool_name=response.tool_name,
            command=response.command or "",
            stdout=response.stdout or "",
            stderr=response.stderr or "",
            error=response.error or "",
            phase=ctx.run_phase,
            success=response.success,
            timed_out=response.timed_out,
        )
        failure_hints = collect_hints(hint_ctx)
        if failure_hints:
            parts.append("\n".join(failure_hints))
        note_failure(signature=ctx.signature, state=ctx.assist_state)

    # Escalation/dispatch hints are only actionable when the tool did NOT produce
    # usable output — appending "next tool" suggestions after a successful run is
    # the advisory-nudge pattern that duplicates the skills + phase-readiness the
    # agent already holds. Compute them only on failure/empty.
    if not useful_output:
        try:
            meta = build_orchestration_meta(
                response,
                target=ctx.target,
                params=ctx.params,
                engagement_id=ctx.engagement_id,
                run_id=ctx.run_id,
                run_phase=ctx.run_phase,
                assist_state=ctx.assist_state,
            )
            hints = format_orchestration_hints(meta, assist_state=ctx.assist_state)
            if hints:
                parts.append(hints)
        except Exception as exc:
            logger.debug("Orchestration hints skipped: %s", exc)

    snapshot = format_findings_snapshot(
        engagement_id=ctx.engagement_id,
        run_id=ctx.run_id,
    )
    if snapshot:
        parts.append(snapshot)

    situational = build_situational_brief(
        engagement_id=ctx.engagement_id,
        run_id=ctx.run_id,
        target=ctx.target,
        phase=ctx.run_phase,
        assist_state=ctx.assist_state,
        user_goal=ctx.user_goal,
    )
    if situational:
        parts.append(situational)

    return "\n\n".join(parts)

