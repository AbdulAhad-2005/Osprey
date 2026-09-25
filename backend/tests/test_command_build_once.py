"""build_command_for_tool must run exactly once per docker-exec tool call.

Previously it ran twice: once as tool_execution's fail-fast preview, then
again independently inside MCPClient._call_via_docker_exec from the same
params. Nothing enforced the two builds stayed identical (params mutate
between them), and the second build was pure waste. Fix: the preview build's
output is threaded through as `prebuilt_command` and reused verbatim.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from osprey.services.mcp_client import MCPClient


def _client() -> MCPClient:
    client = MCPClient()
    client._use_docker = True
    client._kali_container = "fake-container"
    return client


async def _fake_exec_once(command, timeout, *, run_as_root=False):
    return "ok stdout", "", 0, False


def test_prebuilt_command_skips_rebuild():
    client = _client()

    with patch.object(client, "_is_docker_available", return_value=True), patch(
        "osprey.services.command_builder.build_command_for_tool"
    ) as mock_build, patch.object(client, "_exec_docker_once", side_effect=_fake_exec_once):
        response = asyncio.run(
            client.call_tool(
                "subfinder_scan",
                {"domain": "example.com"},
                timeout=30,
                prebuilt_command="subfinder -d example.com",
            )
        )

    mock_build.assert_not_called()
    assert response.command.endswith("subfinder -d example.com")
    assert response.success is True


def test_no_prebuilt_command_still_builds_exactly_once():
    client = _client()

    with patch.object(client, "_is_docker_available", return_value=True), patch(
        "osprey.services.command_builder.build_command_for_tool",
        return_value="subfinder -d example.com",
    ) as mock_build, patch.object(client, "_exec_docker_once", side_effect=_fake_exec_once):
        response = asyncio.run(
            client.call_tool(
                "subfinder_scan",
                {"domain": "example.com"},
                timeout=30,
            )
        )

    mock_build.assert_called_once()
    assert response.command.endswith("subfinder -d example.com")
