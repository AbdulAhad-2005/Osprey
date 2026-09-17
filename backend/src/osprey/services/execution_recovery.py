"""Execution recovery — shadow-mode classify-and-recommend engine (Component 1).

Minimal v1 table by design (see the plan this implements): four error types,
fixed-order strategies, no history-based reordering — only a negative filter
against genuinely repeated failures this engagement. Ships in SHADOW MODE:
classify and log what would happen, never act, until real observations (see
recovery_observation_store) clear the flip threshold for a given error type
(currently: none are enforced — this module has no enforcement path yet).

Classification is gated on exit code FIRST. Many tools print benign strings
("connection refused" on a closed port, normal nmap output) inside a
SUCCESSFUL run — regex-matching stderr text of a call that already succeeded
would misclassify it. Only classify when the call actually failed (non-zero
exit) or the platform's existing empty-success signal fired.
"""

from __future__ import annotations

import logging
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ErrorType(str, Enum):
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    EMPTY_RESULT = "empty_result"  # not a failure — a legitimately-empty run


class RecoveryAction(str, Enum):
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TOOL = "switch_tool"


@dataclass(frozen=True)
class RecoveryStrategy:
    action: RecoveryAction
    max_attempts: int = 3
    backoff_seconds: float = 5.0
    backoff_multiplier: float = 2.0
    # EMPTY_RESULT-specific: don't spin on a legitimately-empty, correct answer
    # (e.g. whois on an unregistered domain) by retrying identically forever.
    requires_param_change: bool = False


# Patterns only ever checked against a call that ALREADY failed (non-zero exit
# or empty-success) — never against successful output. Order doesn't matter
# within a type; first match wins across types, TIMEOUT checked first since
# it's the most common and least ambiguous signal.
_ERROR_PATTERNS: list[tuple[ErrorType, re.Pattern[str]]] = [
    (ErrorType.TIMEOUT, re.compile(r"(?i)\btimed?\s*out\b|\btimeout\b")),
    (ErrorType.RATE_LIMITED, re.compile(r"(?i)rate.?limit|too many requests|\b429\b|throttl")),
    (
        ErrorType.TOOL_NOT_FOUND,
        re.compile(r"(?i)command not found|no such file or directory|executable not found"),
    ),
]

_RECOVERY_STRATEGIES: dict[ErrorType, list[RecoveryStrategy]] = {
    ErrorType.TIMEOUT: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, max_attempts=2),
        RecoveryStrategy(RecoveryAction.RETRY_WITH_REDUCED_SCOPE, max_attempts=1),
        RecoveryStrategy(RecoveryAction.SWITCH_TOOL, max_attempts=1),
    ],
    ErrorType.RATE_LIMITED: [
        RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, max_attempts=3, backoff_seconds=15.0),
    ],
    ErrorType.TOOL_NOT_FOUND: [
        RecoveryStrategy(RecoveryAction.SWITCH_TOOL, max_attempts=1),
    ],
    ErrorType.EMPTY_RESULT: [
        RecoveryStrategy(
            RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
            max_attempts=1,
            requires_param_change=True,
        ),
    ],
}  # fixed order — no history-based reordering in v1


def classify_error(
    *,
    exit_code: int,
    stdout: str = "",
    stderr: str = "",
    empty_success: bool = False,
) -> ErrorType | None:
    """None = not classifiable as a recovery-relevant condition (either the
    call succeeded with real output, or the failure doesn't match a known
    pattern yet — v1's table is deliberately small)."""
    if empty_success and exit_code == 0:
        return ErrorType.EMPTY_RESULT
    if exit_code == 0:
        # A zero-exit, non-empty run is a success — never classify its stderr
        # text as an error, no matter what strings appear in it.
        return None
    blob = f"{stdout}\n{stderr}"
    for error_type, pattern in _ERROR_PATTERNS:
        if pattern.search(blob):
            return error_type
    return None


def strategies_for(error_type: ErrorType) -> list[RecoveryStrategy]:
    return list(_RECOVERY_STRATEGIES.get(error_type, []))


def next_strategy(
    error_type: ErrorType,
    attempt: int,
    *,
    already_failed_twice: bool = False,
) -> RecoveryStrategy | None:
    """attempt is 1-indexed (this is the Nth attempt about to be made).
    already_failed_twice: negative filter only — if this exact tool+error_type
    combination has already failed twice this engagement, don't recommend the
    same strategy a third time. No positive history-based reordering (see
    module docstring / the plan this implements for why that was dropped)."""
    strategies = strategies_for(error_type)
    if not strategies:
        return None
    idx = attempt - 1
    if idx < 0 or idx >= len(strategies):
        return None
    if already_failed_twice and idx == 0:
        # Skip straight to the second strategy (if any) rather than
        # recommending the one that already failed twice in a row.
        return strategies[1] if len(strategies) > 1 else None
    return strategies[idx]


# --- Shared mcp-servers bridge (used by the real docker-exec retry below) ---
_MCP_ROOT = Path(__file__).resolve().parents[4] / "mcp-servers"


def ensure_mcp_path() -> None:
    """Prime sys.path so mcp-servers/_core is importable — used by
    real_retry_decision() below (and mcp_client.py's docker-exec retry loop),
    so this lives in exactly one place rather than being copy-pasted per caller."""
    root = str(_MCP_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


# --- Real (non-shadow) retry decision for the docker-exec path ---
#
# Traced this session: mcp_client.py's _call_via_docker_exec (the platform's
# actual active execution path) builds a raw command string and runs it via a
# single docker-exec subprocess call — it never invokes a tool module's own
# run()/run_tool(), so _core/error_handler.py's IntelligentErrorHandler,
# despite being real, complete, working code, was architecturally unreachable
# in practice. This is the wiring that puts it to actual use, reusing its
# classification + tool_alternatives/parameter_adjustments data (real,
# hand-tuned) rather than re-deriving equivalent logic a second time — the
# retry LOOP mechanics (subprocess handling, timeouts) stay in mcp_client.py,
# which already owns them; this function owns only the decision.
#
# Relationship to Component 1 (execution_recovery.classify_error/next_strategy,
# above): that classifier is backend-side, cross-call, SHADOW-only, building
# durable evidence for an eventual data-driven enforcement decision. This is
# in-call, single-request, and REAL (acts immediately) — a different layer,
# not a duplicate. If a call retries here and still fails, Component 1's
# shadow classifier still runs afterward on the final result (in
# tool_execution.py) and will correctly see a real failure, not a phantom one
# — but its own retry recommendation would be redundant with what already
# happened here. Not a problem today (Component 1 never acts, shadow only),
# but worth remembering if/when Component 1's classifier is ever enforced for
# an error type also handled here: the two would need the same "already
# tried, don't re-suggest it" handoff signal already used elsewhere in this
# module, not independent re-attempts.
def real_retry_decision(
    *,
    tool_name: str,
    command: str,
    params: dict[str, Any],
    error_message: str,
    target: str,
    attempt_count: int,
    timed_out: bool,
) -> dict[str, Any] | None:
    """None = the bridge/engine is unavailable (never raises into the caller —
    a missing mcp-servers mount must degrade to today's no-retry behavior, not
    break execution). Otherwise returns process_tool_failure()'s decision dict
    plus a rebuilt command string when the decision calls for one."""
    try:
        ensure_mcp_path()
        from _core.error_handler import (  # type: ignore[import-not-found]
            RecoveryAction,
            process_tool_failure,
            rebuild_command_with_params,
        )

        decision = process_tool_failure(
            tool_name,
            error_message,
            parameters=params,
            target=target,
            attempt_count=attempt_count,
            timed_out=timed_out,
        )
        action = decision["recovery_action"]
        rebuilt_command = command
        if action in (
            RecoveryAction.RETRY_WITH_REDUCED_SCOPE.value,
            RecoveryAction.ADJUST_PARAMETERS.value,
        ):
            rebuilt_command = rebuild_command_with_params(
                tool_name, command, decision.get("adjusted_parameters") or {}
            )
        if decision.get("alternative_tool"):
            from osprey.services.tool_registry import get_tool_definition, resolve_tool_name

            resolved = resolve_tool_name(str(decision["alternative_tool"]))
            decision["alternative_tool"] = resolved if get_tool_definition(resolved) else None
        decision["rebuilt_command"] = rebuilt_command
        return decision
    except Exception as exc:  # noqa: BLE001
        logger.debug("real_retry_decision unavailable for %s: %s", tool_name, exc)
        return None
