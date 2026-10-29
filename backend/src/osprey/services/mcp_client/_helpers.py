from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

from osprey.schemas.tools import (
    ToolDefinition,
)
from osprey.services.output_budget import truncate_stdout as _budget_truncate_stdout

logger = logging.getLogger(__name__)

# Path to the mcp-servers directory relative to the project root
_MCP_SERVERS_DIR = Path(__file__).resolve().parents[4] / "mcp-servers"

# StreamReader buffer cap for the native/stdio MCP servers. A tool's whole
# JSON-RPC response arrives as a single newline-terminated line read via
# ``readline()``; the asyncio default (64 KiB) overflows on real scan output
# (crt.sh / amass / httpx / dnsx results) with "Separator is not found, and
# chunk exceed the limit". 64 MiB comfortably holds a full tool response.
# (The docker-exec one-shot path uses ``communicate()`` and is unaffected.)
_STDIO_LIMIT = 64 * 1024 * 1024

# Forward selected OSINT / credential-intel secrets into Kali on each docker exec
# (compose env alone is not enough if the key was added after the container
# started). Private overlays (for example, a company credential manager) add
# their own env
# names via OSPREY_KALI_ENV_FORWARD (comma-separated) — no code change needed.
_KALI_ENV_FORWARD_BASE = (
    "SHODAN_API_KEY",
    "INTELX_API_KEY",
    "INTELX_IDENTITY_API_KEY",
    "INTELX_API_BASE",
    "INTELX_IDENTITY_BASE",
    "RESECURITY_API_KEY",
    "RESECURITY_API_BASE",
    "RESECURITY_ENDPOINT",
    "RESECURITY_QUERY_PARAM",
    "RESECURITY_AUTH_HEADER",
    "RESECURITY_AUTH_SCHEME",
)
_KALI_ENV_FORWARD = _KALI_ENV_FORWARD_BASE + tuple(
    name.strip()
    for name in (os.environ.get("OSPREY_KALI_ENV_FORWARD") or "").split(",")
    if name.strip()
)

# Execution PATH for `docker exec` into Kali. A bare `docker exec` (and a non-login
# `bash -c`) does NOT source the mcpuser profile, so it misses ~/.local/bin — where
# pipx shims and `pip install --user` binaries (many OSINT tools) live. We prepend
# it (and /usr/local/bin) to the standard image PATH so those tools resolve exactly
# like apt/go tools. Keep in sync with kali-tools/Dockerfile ENV PATH.
_KALI_EXEC_PATH = (
    "/home/mcpuser/.local/bin:/opt/go/bin:/usr/local/go/bin:"
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

# A handful of scanners the recon/network engine leans on the most. Used only to
# answer "can this environment actually run tools?" for the /scan --engine
# preflight — not an exhaustive tool check (that's /tools). If the Kali container
# is down AND none of these resolve on the host PATH, execution silently falls
# back to running "natively" inside the backend container, which has no scanners,
# so every tool call fails. The preflight catches exactly that case up front.
_CORE_ENGINE_TOOLS = ("subfinder", "httpx", "naabu", "nmap", "dnsx")


def _truncate_stdout(stdout: str, tool_name: str = "") -> str:
    """Cap raw subprocess capture to this tool's output-budget ceiling.

    This is the earliest point stdout exists in memory (straight off the
    subprocess pipe) — the one place that used to apply its OWN unrelated
    50_000-char, head-only, no-tail cap regardless of tool, ahead of where
    ``tool_execution.execute_tool_request`` writes the full artifact and
    applies the real per-tool policy. That meant anything past 50KB was lost
    for good, from both the live view AND the artifact, no matter how
    generous the later policy was. Deferring to the shared policy here
    instead means: (a) one number, not two independently-tuned ones, and
    (b) the head+tail preservation the later layer already does, so the tail
    of a big dump survives even at this earliest capture point.
    """
    return _budget_truncate_stdout(tool_name, stdout)


async def _kill_and_reap(proc: asyncio.subprocess.Process | None) -> None:
    """Kill a subprocess and wait for it so it doesn't linger as a zombie.

    On timeout, ``asyncio.wait_for(proc.communicate(), ...)`` only cancels the
    *wait* — the underlying ``docker exec`` process (and the real scan running
    inside Kali) keeps running unless explicitly killed. Left unreaped across
    enough timed-out long scans (nmap -p-, full-range naabu, etc.), this leaks
    file descriptors/process slots until the backend stops accepting new tool
    calls — the "everything eventually hangs" symptom that only clears on a
    full restart. Every timeout branch that spawned a process must call this.
    """
    if proc is None or proc.returncode is not None:
        return
    try:
        proc.kill()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        logger.warning("subprocess pid=%s did not exit after kill", getattr(proc, "pid", "?"))


async def _drain_partial(
    proc: asyncio.subprocess.Process | None, *, cap: int = 65536, wait: float = 0.5
) -> tuple[str, str]:
    """Best-effort read of whatever stdout/stderr is already buffered after a timeout.

    ``asyncio.wait_for(proc.communicate(), timeout=...)`` discards everything the
    process had already written once it raises ``TimeoutError`` — the caller never
    sees output that arrived a moment before the deadline. This does a short,
    bounded, non-fatal read of each stream (whatever the OS pipe buffer already
    holds returns immediately; nothing new arriving within ``wait`` seconds just
    means an empty result) so a timed-out tool still comes back with partial
    output instead of nothing.
    """
    if proc is None:
        return "", ""

    async def _read(stream: asyncio.StreamReader | None) -> bytes:
        if stream is None:
            return b""
        try:
            return await asyncio.wait_for(stream.read(cap), timeout=wait)
        except Exception:
            return b""

    out_b, err_b = await asyncio.gather(_read(proc.stdout), _read(proc.stderr))
    return out_b.decode(errors="replace"), err_b.decode(errors="replace")


def _parse_tool_output(
    tool_def: ToolDefinition,
    *,
    command: str,
    returncode: int | None,
    stdout: str,
    stderr: str,
    timed_out: bool = False,
) -> dict[str, Any]:
    """Run a tool's own ``parse()`` against whatever stdout/stderr we have.

    Shared by the normal-completion and timeout paths in ``_call_via_docker_exec``
    so a tool whose script prints incrementally (see e.g. tech_stack_analyze.py's
    ``emit()``) still gets structured findings out of a partial, timed-out run —
    not just an unparsed raw-text blob.
    """
    try:
        import importlib.util as _iu
        import sys as _sys

        _mcp_str = str(_MCP_SERVERS_DIR)
        if _mcp_str not in _sys.path:
            _sys.path.insert(0, _mcp_str)

        module_path = _MCP_SERVERS_DIR / tool_def.mcp_server.value / "tools" / f"{tool_def.name}.py"
        if not module_path.exists():
            return {}
        spec = _iu.spec_from_file_location(f"_parse_{tool_def.name}", module_path)
        if not (spec and spec.loader):
            return {}
        mod = _iu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        parse_fn = getattr(mod, "parse", None)
        if not parse_fn:
            return {}

        from _core.result import ToolResult

        tr = ToolResult(
            tool_name=tool_def.name,
            command=command,
            success=returncode == 0 and not timed_out,
            returncode=returncode,
            # Not the real duration (see plan 19) — this ToolResult is a
            # throwaway, feeding only the tool's own parse() for structured
            # extraction; the actual ToolExecutionResponse returned to the
            # caller carries the real wall-clock duration_seconds instead.
            duration_seconds=0.0,
            raw_stdout=stdout,
            raw_stderr=stderr,
            timed_out=timed_out,
        )
        parsed = parse_fn(tr)
        return parsed if isinstance(parsed, dict) else {}
    except Exception as exc:
        logger.debug("Could not parse tool output for %s: %s", tool_def.name, exc)
        return {}


class MCPServerNotRunning(Exception):
    """Raised when the requested MCP server process is not available."""


class MCPClientError(Exception):
    """Raised on MCP tool execution failures."""


