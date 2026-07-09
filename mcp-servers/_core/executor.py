"""Safe subprocess executor — arg-list execution, no shell (hardened vs HexStrike shell=True)."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from typing import Optional, Sequence, Union

from .result import ToolResult

CommandInput = Union[str, Sequence[str]]


class ExecutorError(RuntimeError):
    pass


def _resolve_command(command: CommandInput) -> tuple[list[str], str]:
    if isinstance(command, str):
        parts = shlex.split(command, posix=(os.name != "nt"))
        if not parts:
            raise ExecutorError("Empty command")
        return parts, command
    parts = [str(p) for p in command if str(p)]
    if not parts:
        raise ExecutorError("Empty command")
    return parts, " ".join(shlex.quote(p) for p in parts)


def run_command(
    tool_name: str,
    command: CommandInput,
    *,
    timeout: int = 300,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
    sudo: bool = False,
) -> ToolResult:
    """Execute *command* and capture full stdout/stderr without a shell."""
    args, display = _resolve_command(command)
    binary = args[0]
    if shutil.which(binary) is None and not os.path.isabs(binary):
        return ToolResult(
            tool_name=tool_name,
            command=display,
            success=False,
            returncode=None,
            duration_seconds=0.0,
            error=f"Binary not found: {binary}",
        )

    exec_args = (["sudo", "-n", *args] if sudo else args)
    start = time.monotonic()
    timed_out = False
    stdout = ""
    stderr = ""
    returncode: Optional[int] = None

    try:
        completed = subprocess.run(
            exec_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            shell=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        returncode = completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        returncode = -1
    except OSError as exc:
        return ToolResult(
            tool_name=tool_name,
            command=display,
            success=False,
            returncode=None,
            duration_seconds=time.monotonic() - start,
            error=str(exc),
        )

    duration = time.monotonic() - start
    success = returncode == 0 and not timed_out

    return ToolResult(
        tool_name=tool_name,
        command=display,
        success=success,
        returncode=returncode,
        duration_seconds=duration,
        raw_stdout=stdout,
        raw_stderr=stderr,
        timed_out=timed_out,
        error=None if success else (stderr.strip() or f"exit code {returncode}"),
    )
