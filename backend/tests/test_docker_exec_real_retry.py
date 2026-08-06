"""Real (non-shadow) retry loop in mcp_client.py::_call_via_docker_exec.

Puts the already-built, previously-unreachable _core/error_handler.py engine
to actual use. Mocks _exec_docker_once to control the failure/success
sequence deterministically and avoid real docker calls / real sleeps.

No pytest-asyncio in this project (only anyio as a transitive FastAPI/httpx
dependency, unconfigured for test markers) — driving the coroutines directly
via asyncio.run() from plain sync test functions instead of introducing a new
async-test convention for one file.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from pentest_platform.schemas.tools import ToolDefinition, ToolCategory, ToolSafetyLevel, MCPServerCategory
from pentest_platform.services.mcp_client import MCPClient


def _tool_def(name: str = "nmap_service_scan") -> ToolDefinition:
    return ToolDefinition(
        name=name,
        category=ToolCategory.NETWORK,
        description="test",
        executable="nmap",
        safety_level=ToolSafetyLevel.ACTIVE,
        mcp_server=MCPServerCategory.NETWORK,
    )


def test_succeeds_on_first_attempt_no_retry_history():
    client = MCPClient.__new__(MCPClient)
    client._exec_docker_once = AsyncMock(return_value=("open ports found", "", 0, False))

    response = asyncio.run(
        client._call_via_docker_exec(
            "nmap_service_scan", _tool_def(), {"target": "example.com", "ports": "80"}, timeout=60
        )
    )
    assert response.success is True
    assert response.recovery_info == {}
    client._exec_docker_once.assert_awaited_once()


def test_timeout_then_success_records_real_recovery_history():
    client = MCPClient.__new__(MCPClient)
    client._exec_docker_once = AsyncMock(
        side_effect=[
            ("", "Operation timed out", None, True),
            ("open ports found", "", 0, False),
        ]
    )
    with patch("pentest_platform.services.execution_recovery.real_retry_decision") as mock_decision:
        mock_decision.return_value = {
            "error_type": "timeout",
            "recovery_action": "retry_with_reduced_scope",
            "should_retry": True,
            "backoff_seconds": 0.0,
            "alternative_tool": None,
            "rebuilt_command": "nmap -sV -p 80 example.com -T2",
        }
        response = asyncio.run(
            client._call_via_docker_exec(
                "nmap_service_scan", _tool_def(), {"target": "example.com", "ports": "80"}, timeout=60
            )
        )

    assert response.success is True
    assert response.recovery_info["attempts_made"] == 2
    assert response.recovery_info["recovery_applied"] is True
    assert len(response.recovery_info["recovery_history"]) == 1
    assert response.recovery_info["recovery_history"][0]["recovery_action"] == "retry_with_reduced_scope"
    assert client._exec_docker_once.await_count == 2
    # The rebuilt command from the decision must actually be used for retry 2.
    second_call_command = client._exec_docker_once.await_args_list[1].args[0]
    assert second_call_command == "nmap -sV -p 80 example.com -T2"


def test_exhausts_max_attempts_and_reports_honestly():
    client = MCPClient.__new__(MCPClient)
    client._exec_docker_once = AsyncMock(return_value=("", "Operation timed out", None, True))
    with patch("pentest_platform.services.execution_recovery.real_retry_decision") as mock_decision:
        mock_decision.return_value = {
            "error_type": "timeout",
            "recovery_action": "retry_with_backoff",
            "should_retry": True,
            "backoff_seconds": 0.0,
            "alternative_tool": None,
            "rebuilt_command": None,
        }
        response = asyncio.run(
            client._call_via_docker_exec(
                "nmap_service_scan", _tool_def(), {"target": "example.com"}, timeout=60
            )
        )

    assert response.success is False
    assert response.recovery_info["attempts_made"] == 3  # max_attempts cap, not unbounded
    assert client._exec_docker_once.await_count == 3


def test_switch_to_alternative_tool_stops_retrying_and_suggests():
    client = MCPClient.__new__(MCPClient)
    client._exec_docker_once = AsyncMock(return_value=("", "command not found", 127, False))
    with patch("pentest_platform.services.execution_recovery.real_retry_decision") as mock_decision:
        mock_decision.return_value = {
            "error_type": "tool_not_found",
            "recovery_action": "switch_to_alternative_tool",
            "should_retry": False,
            "backoff_seconds": 0.0,
            "alternative_tool": "rustscan_fast_scan",
            "rebuilt_command": None,
        }
        response = asyncio.run(
            client._call_via_docker_exec(
                "nmap_service_scan", _tool_def(), {"target": "example.com"}, timeout=60
            )
        )

    assert response.success is False
    assert response.alternative_tool_suggested == "rustscan_fast_scan"
    # Must NOT keep retrying once the decision says stop — only 1 real
    # execution attempt, the recovery engine is consulted once before halting.
    assert client._exec_docker_once.await_count == 1
    assert response.recovery_info["final_action"] == "switch_to_alternative_tool"


def test_recovery_engine_unavailable_degrades_to_no_retry_not_a_crash():
    # If the mcp-servers bridge is missing/broken, real_retry_decision()
    # returns None (per its own contract) — must degrade gracefully to
    # today's original no-retry behavior, never raise into the caller.
    client = MCPClient.__new__(MCPClient)
    client._exec_docker_once = AsyncMock(return_value=("", "some error", 1, False))
    with patch("pentest_platform.services.execution_recovery.real_retry_decision", return_value=None):
        response = asyncio.run(
            client._call_via_docker_exec(
                "nmap_service_scan", _tool_def(), {"target": "example.com"}, timeout=60
            )
        )

    assert response.success is False
    assert client._exec_docker_once.await_count == 1
    assert response.recovery_info["final_action"] == "recovery_engine_unavailable"
