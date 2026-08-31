from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

DETAIL_MODES = ("compact", "preview", "verbose")
_detail_mode = "preview"


@dataclass
class ToolRecord:
    id: int
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    source: str = "commander"
    phase: str = ""
    tool_call_id: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    success: bool | None = None
    duration_seconds: float = 0.0
    preview: str = ""
    command: str = ""
    returncode: int | None = None
    stdout_path: str = ""
    stderr_path: str = ""
    stdout: str = ""
    stderr: str = ""
    finding_titles: list[str] = field(default_factory=list)
    display_preview: list[str] = field(default_factory=list)
    display_quiet: bool = False
    cache_hit: bool = False
    next_hint: str = ""

    @property
    def status_text(self) -> str:
        if self.success is None:
            return "running"
        return "ok" if self.success else "failed"


class ToolTranscript:
    """In-memory transcript for expanding tool calls during one CLI session."""

    def __init__(self) -> None:
        self._next_id = 1
        self._records: list[ToolRecord] = []

    def start(self, data: dict[str, Any], *, source: str = "commander") -> ToolRecord:
        tool_call_id = str(data.get("tool_call_id") or "")
        if tool_call_id:
            existing = self._find_by_tool_call_id(tool_call_id)
            if existing is not None:
                return existing
        rec = ToolRecord(
            id=self._next_id,
            tool_name=str(data.get("tool_name") or "?"),
            arguments=dict(data.get("arguments") or {}),
            source=source or "commander",
            phase=str(data.get("phase") or ""),
            tool_call_id=tool_call_id,
            display_quiet=bool(data.get("display_quiet", False)),
        )
        self._next_id += 1
        self._records.append(rec)
        return rec

    def end(self, data: dict[str, Any], *, source: str = "commander") -> ToolRecord:
        tool_name = str(data.get("tool_name") or "?")
        tool_call_id = str(data.get("tool_call_id") or "")
        rec = self._match_running(tool_name, tool_call_id, source)
        if rec is None:
            rec = self.start(data, source=source)
        rec.ended_at = datetime.now(timezone.utc)
        rec.success = bool(data.get("success", False))
        rec.duration_seconds = float(data.get("duration_seconds") or 0)
        rec.preview = str(data.get("preview") or "")
        rec.command = str(data.get("command") or "")
        rec.returncode = data.get("returncode")
        raw_artifacts = data.get("artifacts")
        artifacts = raw_artifacts if isinstance(raw_artifacts, dict) else {}
        rec.stdout_path = str(
            data.get("stdout_path") or artifacts.get("stdout_path") or ""
        )
        rec.stderr_path = str(
            data.get("stderr_path") or artifacts.get("stderr_path") or ""
        )
        rec.stdout = str(data.get("stdout") or "")
        rec.stderr = str(data.get("stderr") or "")
        rec.finding_titles = list(data.get("finding_titles") or [])
        display_preview = data.get("display_preview") or []
        if isinstance(display_preview, str):
            display_preview = [display_preview]
        rec.display_preview = [str(item) for item in display_preview if str(item).strip()]
        rec.display_quiet = bool(data.get("display_quiet", rec.display_quiet))
        rec.cache_hit = bool(data.get("cache_hit", False))
        rec.next_hint = str(data.get("next_hint") or "")
        return rec

    def _find_by_tool_call_id(self, tool_call_id: str) -> ToolRecord | None:
        for rec in reversed(self._records):
            if rec.tool_call_id == tool_call_id:
                return rec
        return None

    def _match_running(
        self, tool_name: str, tool_call_id: str, source: str
    ) -> ToolRecord | None:
        for rec in reversed(self._records):
            if rec.success is not None:
                continue
            if tool_call_id and rec.tool_call_id == tool_call_id:
                return rec
            if not tool_call_id and rec.tool_name == tool_name and rec.source == source:
                return rec
        return None

    def get(self, ref: str | int) -> ToolRecord | None:
        try:
            number = int(str(ref).lstrip("#"))
        except ValueError:
            return None
        for rec in self._records:
            if rec.id == number:
                return rec
        return None

    def recent(self, limit: int = 12) -> list[ToolRecord]:
        return self._records[-limit:]

    def clear(self) -> None:
        self._records.clear()
        self._next_id = 1


def set_detail_mode(mode: str) -> str:
    global _detail_mode
    if mode not in DETAIL_MODES:
        raise ValueError(f"detail mode must be one of {', '.join(DETAIL_MODES)}")
    _detail_mode = mode
    return _detail_mode


def cycle_detail_mode() -> str:
    idx = DETAIL_MODES.index(_detail_mode)
    return set_detail_mode(DETAIL_MODES[(idx + 1) % len(DETAIL_MODES)])


def get_detail_mode() -> str:
    return _detail_mode


tool_transcript = ToolTranscript()
