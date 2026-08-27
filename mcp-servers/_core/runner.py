"""High-level tool runner: cache + executor + IntelligentErrorHandler recovery + parse hook."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Callable, Optional

from .cache import CommandCache
from .error_handler import (
    RecoveryAction,
    degradation_manager,
    determine_operation_type,
    process_tool_failure,
    rebuild_command_with_params,
)
from .executor import run_command
from .result import ToolResult

_DEFAULT_CACHE = CommandCache()


def run_tool(
    tool_name: str,
    command: str,
    *,
    params: Optional[dict[str, Any]] = None,
    timeout: int = 300,
    use_cache: bool = True,
    use_recovery: bool = False,
    max_attempts: int = 3,
    parse_fn: Optional[Callable[[ToolResult], dict[str, Any]]] = None,
    rebuild_command_fn: Optional[Callable[[dict[str, Any]], str]] = None,
    cache: Optional[CommandCache] = None,
    cwd: Optional[str] = None,
    sudo: bool = False,
) -> dict[str, Any]:
    """
    Execute a shell-style command string safely (tokenised, no shell).

    When *use_recovery* is True, failures flow through the
    ``IntelligentErrorHandler`` (retry/backoff, param adjust, tool switch,
    human escalation, graceful degradation).
    """
    params = params or {}
    cache = cache or _DEFAULT_CACHE
    recovery_history: list[dict[str, Any]] = []
    attempt = 0
    last_result: Optional[ToolResult] = None
    current_command = command
    current_params = dict(params)

    while attempt < max_attempts:
        attempt += 1
        if use_cache:
            cached = cache.get(current_command, current_params)
            if cached is not None:
                cached = dict(cached)
                cached["cache_hit"] = True
                return cached

        result = run_command(tool_name, current_command, timeout=timeout, cwd=cwd, sudo=sudo)
        last_result = result

        if result.success:
            if parse_fn:
                result.parsed = parse_fn(result)
            payload = result.to_dict()
            if use_recovery:
                payload["recovery_info"] = {
                    "attempts_made": attempt,
                    "recovery_applied": len(recovery_history) > 0,
                    "recovery_history": recovery_history,
                }
            # Never cache empty "success" — looks like a working tool that returns 0 results.
            stdout = (result.raw_stdout or "").strip()
            if use_cache and stdout:
                cache.set(current_command, current_params, payload)
            elif use_cache and not stdout:
                payload["warning"] = (
                    "Tool exited successfully but produced empty stdout "
                    "(likely missing/wrong target param or no findings)."
                )
            return payload

        if not use_recovery:
            break

        error_message = result.raw_stderr or result.error or "Unknown error"
        decision = process_tool_failure(
            tool_name,
            error_message,
            parameters=current_params,
            target=str(current_params.get("target", current_params.get("url", "unknown"))),
            attempt_count=attempt,
            timed_out=result.timed_out,
        )
        recovery_history.append(
            {
                "attempt": attempt,
                "error": error_message[:500],
                "recovery_action": decision["recovery_action"],
                "error_type": decision["error_type"],
                "timestamp": datetime.now().isoformat(),
            }
        )

        action = RecoveryAction(decision["recovery_action"])

        if action == RecoveryAction.RETRY_WITH_BACKOFF:
            time.sleep(decision["backoff_seconds"] or min(2**attempt, 30))
            continue

        if action in (RecoveryAction.RETRY_WITH_REDUCED_SCOPE, RecoveryAction.ADJUST_PARAMETERS):
            current_params = decision["adjusted_parameters"]
            if rebuild_command_fn:
                current_command = rebuild_command_fn(current_params)
            else:
                current_command = rebuild_command_with_params(tool_name, command, current_params)
            continue

        if action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
            payload = result.to_dict()
            payload["recovery_decision"] = decision
            payload["alternative_tool_suggested"] = decision.get("alternative_tool")
            payload["recovery_info"] = {
                "attempts_made": attempt,
                "recovery_applied": True,
                "recovery_history": recovery_history,
                "final_action": "tool_switch_suggested",
            }
            return payload

        if action == RecoveryAction.ESCALATE_TO_HUMAN:
            payload = result.to_dict()
            payload["recovery_decision"] = decision
            payload["human_escalation"] = decision.get("human_escalation")
            payload["recovery_info"] = {
                "attempts_made": attempt,
                "recovery_applied": True,
                "recovery_history": recovery_history,
                "final_action": "human_escalation",
            }
            return payload

        if action == RecoveryAction.GRACEFUL_DEGRADATION:
            operation = determine_operation_type(tool_name)
            degraded = degradation_manager.handle_partial_failure(
                operation,
                result.to_dict(),
                [tool_name],
            )
            degraded["recovery_decision"] = decision
            degraded["recovery_info"] = {
                "attempts_made": attempt,
                "recovery_applied": True,
                "recovery_history": recovery_history,
                "final_action": "graceful_degradation",
            }
            return degraded

        if action == RecoveryAction.ABORT_OPERATION:
            break

    assert last_result is not None
    if parse_fn:
        last_result.parsed = parse_fn(last_result)
    payload = last_result.to_dict()
    payload["recovery_decision"] = process_tool_failure(
        tool_name,
        last_result.raw_stderr or last_result.error or "Unknown error",
        parameters=current_params,
        attempt_count=attempt,
        timed_out=last_result.timed_out,
    )
    if use_recovery:
        payload["recovery_info"] = {
            "attempts_made": attempt,
            "recovery_applied": len(recovery_history) > 0,
            "recovery_history": recovery_history,
            "final_action": "all_attempts_exhausted" if attempt >= max_attempts else "aborted",
        }
    return payload


def default_parse(_result: ToolResult) -> dict[str, Any]:
    """Stub parser — Summary Agent can consume raw output until per-tool parsers land."""
    return {"findings": [], "note": "parse not implemented for this tool yet"}
