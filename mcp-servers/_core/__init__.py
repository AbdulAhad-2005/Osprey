"""Shared execution core for harvested HexStrike tools."""

from .cache import CommandCache
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
from .executor import ExecutorError, run_command
from .recovery import alternatives_for_tool, classify_error, suggest_fallback_chain
from .registry import GLOBAL_REGISTRY, RegisteredTool, ToolRegistry
from .result import ToolResult
from .runner import default_parse, run_tool

__all__ = [
    "CommandCache",
    "ErrorContext",
    "ErrorType",
    "ExecutorError",
    "GLOBAL_REGISTRY",
    "GracefulDegradation",
    "IntelligentErrorHandler",
    "RecoveryAction",
    "RecoveryStrategy",
    "RegisteredTool",
    "ToolRegistry",
    "ToolResult",
    "alternatives_for_tool",
    "classify_error",
    "degradation_manager",
    "default_parse",
    "determine_operation_type",
    "error_handler",
    "normalize_tool_key",
    "process_tool_failure",
    "rebuild_command_with_params",
    "run_command",
    "run_tool",
    "suggest_fallback_chain",
]
