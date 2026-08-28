"""Subprocess executor for tool commands.

A tool's ``build_command()`` returns a *shell-style command string* — the same
contract the docker path honors by running it via ``bash -c``. These strings
legitimately use shell features: ``$( ... )`` path selection (container-vs-host),
here-docs (``cat > file << EOF``), pipes, and ``if`` guards. Tokenising them with
``shlex.split`` (the old behaviour) silently breaks every one of those — a
``$(`` becomes a literal argv entry, a here-doc trips "No closing quotation".

So a **string** command is executed through ``bash -c`` here too, exactly as the
docker path does, keeping the two execution modes consistent. This is not
arbitrary-shell exposure: the command comes from a trusted dev-authored
``build_command()`` with every user-supplied param already ``shlex.quote``'d;
free-form shell for the LLM stays behind the separate allowlisted
``platform_shell`` / ``platform_script`` paths. A **list** command (explicit
argv) still runs directly as argv with no shell.
"""

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


def run_command(
    tool_name: str,
    command: CommandInput,
    *,
    timeout: int = 300,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
    sudo: bool = False,
) -> ToolResult:
    """Execute *command* and capture full stdout/stderr.

    String commands run via ``bash -c`` (shell-style contract, matches docker);
    list commands run as direct argv.
    """
    if isinstance(command, str):
        display = command
        if not command.strip():
            raise ExecutorError("Empty command")
        exec_args = ["bash", "-c", command]
        if sudo:
            exec_args = ["sudo", "-n", *exec_args]
    else:
        args = [str(p) for p in command if str(p)]
        if not args:
            raise ExecutorError("Empty command")
        display = " ".join(shlex.quote(p) for p in args)
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
