"""Backward-compatible re-exports — full handler lives in error_handler.py."""

from __future__ import annotations

from .error_handler import (
    ErrorContext,
    ErrorType,
    GracefulDegradation,
    IntelligentErrorHandler,
    RecoveryAction,
    RecoveryStrategy,
    degradation_manager,
    determine_operation_type,
    error_handler,
    normalize_tool_key,
    process_tool_failure,
    rebuild_command_with_params,
)

# Legacy helpers used by early harvest stubs
FALLBACK_CHAINS = degradation_manager.fallback_chains
TOOL_ALTERNATIVES = error_handler.tool_alternatives


def classify_error(stderr: str, returncode: int | None = None, timed_out: bool = False):
    """Thin wrapper — prefer process_tool_failure() for Summary Agent integration."""
    from dataclasses import dataclass, field

    @dataclass
    class ClassifiedError:
        error_type: ErrorType
        message: str
        suggested_action: RecoveryAction
        alternative_tools: list[str] = field(default_factory=list)

    message = stderr or ("Command timed out" if timed_out else "")
    error_type = error_handler.classify_error(message, TimeoutError() if timed_out else None)
    strategies = error_handler.recovery_strategies.get(error_type, [])
    action = strategies[0].action if strategies else RecoveryAction.ABORT_OPERATION
    return ClassifiedError(
        error_type=error_type,
        message=message.strip()[:500],
        suggested_action=action,
        alternative_tools=[],
    )


def suggest_fallback_chain(operation: str, failed_tools: list[str] | None = None) -> list[str]:
    return degradation_manager.create_fallback_chain(operation, failed_tools)


def alternatives_for_tool(tool_name: str) -> list[str]:
    return error_handler.tool_alternatives.get(normalize_tool_key(tool_name), [])
