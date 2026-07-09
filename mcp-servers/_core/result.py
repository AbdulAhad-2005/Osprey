"""Normalized tool execution result — loss-free raw capture for the Summary Agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ToolResult:
    """
    Result of a single tool invocation.

    Completeness guarantee: ``raw_stdout`` and ``raw_stderr`` always carry the
    full streams from the subprocess. ``parsed`` is optional structured extraction
    for graph ingestion (populated by per-tool ``parse()`` functions).
    """

    tool_name: str
    command: str
    success: bool
    returncode: Optional[int]
    duration_seconds: float
    raw_stdout: str = ""
    raw_stderr: str = ""
    parsed: dict[str, Any] = field(default_factory=dict)
    timed_out: bool = False
    error: Optional[str] = None
    recovery_info: dict[str, Any] = field(default_factory=dict)
    cache_hit: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "command": self.command,
            "success": self.success,
            "returncode": self.returncode,
            "duration_seconds": round(self.duration_seconds, 3),
            "raw_stdout": self.raw_stdout,
            "raw_stderr": self.raw_stderr,
            "stdout": self.raw_stdout,
            "stderr": self.raw_stderr,
            "parsed": self.parsed,
            "timed_out": self.timed_out,
            "error": self.error,
            "recovery_info": self.recovery_info,
            "cache_hit": self.cache_hit,
        }
