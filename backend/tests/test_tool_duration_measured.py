"""Plan 19 — ``duration_seconds`` is a real wall-clock measurement, not a
hardcoded placeholder.

CONFIRMED BUG (found by grepping a real operator export: literally all 492
tool entries across two separate engagement exports showed "duration: 0ms").
Root cause: every ``ToolExecutionResponse`` construction site in
``mcp_client.py`` (the docker-exec path, both native-mode paths, and the
stdio JSON-RPC path) hardcoded ``duration_seconds=0``. Nothing ever measured
real elapsed time, so the CLI/dashboard could never distinguish a genuine
slow re-execution from a cache hit or a replayed event — a real contributor
to the operator's "tools looping back again and again" confusion, since the
one signal that would show "this really did just run for 40s" never existed.

These tests prove real elapsed time is measured by making the fake subprocess
actually sleep, and asserting the reported duration reflects it (not just
checking for a nonzero magic number).
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from osprey.services import mcp_client
from osprey.services.tool_registry import get_tool_definition

_SLEEP_SECONDS = 0.08


def _make_fake_proc(sleep_seconds: float, *, returncode: int = 0):
    proc = MagicMock()
    proc.returncode = returncode

    async def _communicate(input=None):  # noqa: A002 - matches Process.communicate's signature
        await asyncio.sleep(sleep_seconds)
        return b"ok stdout", b""

    proc.communicate = _communicate
    return proc


def test_exec_docker_once_measures_real_elapsed_time():
    client = mcp_client.MCPClient()
    fake_proc = _make_fake_proc(_SLEEP_SECONDS)

    async def _fake_create_subprocess_exec(*args, **kwargs):
        return fake_proc

    with patch("asyncio.create_subprocess_exec", side_effect=_fake_create_subprocess_exec):
        stdout, stderr, returncode, timed_out, duration = asyncio.run(
            client._exec_docker_once("echo hi", timeout=5)
        )

    assert returncode == 0
    assert timed_out is False
    # asyncio.sleep's own timer granularity can return a hair early — allow a
    # small tolerance; the point is proving this is REAL elapsed time (tied to
    # the actual sleep), not that a hardcoded 0 happens to pass a floor check.
    assert duration >= _SLEEP_SECONDS * 0.9, f"expected duration ~{_SLEEP_SECONDS}s, got {duration}"
    assert duration < _SLEEP_SECONDS + 2.0, "duration should reflect the real sleep, not a huge/stuck value"


def test_call_via_docker_exec_propagates_the_real_duration_to_the_response():
    """The duration measured inside _exec_docker_once must survive all the way
    out through ToolExecutionResponse.duration_seconds — not get reset to 0
    by the caller that constructs the response."""
    client = mcp_client.MCPClient()
    tool_def = get_tool_definition("subfinder_scan")
    exec_mock = AsyncMock(return_value=("sub.example.com", "", 0, False, _SLEEP_SECONDS))

    with patch.object(client, "_exec_docker_once", exec_mock):
        response = asyncio.run(client._call_via_docker_exec(
            "subfinder_scan", tool_def, {"domain": "example.com"}, timeout=30,
            prebuilt_command="subfinder -d example.com",
        ))

    assert response.success is True
    assert response.duration_seconds == _SLEEP_SECONDS, (
        f"expected the measured duration to reach the response untouched, got {response.duration_seconds}"
    )
