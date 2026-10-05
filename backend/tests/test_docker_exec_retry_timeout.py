"""_call_via_docker_exec's internal retry loop (max_attempts=3) retried a
TIMED-OUT command with the SAME timeout budget whenever the recovery engine
couldn't actually rewrite it (error_handler.py's rebuild_command_with_params
only knows nmap/gobuster/nuclei/feroxbuster/ffuf — everything else, e.g.
dnsenum, gets a no-op "rebuilt" command identical to the original). A retry
that changes nothing after a timeout is guaranteed to time out again,
identically — this silently multiplied a tool's configured timeout ceiling
by up to 3x (observed live: a 60s-budgeted dnsenum_scan opportunity actually
ran 370s). Same principle as tool_execution.py's auto-fallback guard: a
same-invocation retry must change something to be worth attempting.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from osprey.services import mcp_client
from osprey.services.tool_registry import get_tool_definition


def test_identical_command_after_timeout_is_not_retried():
    client = mcp_client.MCPClient()
    tool_def = get_tool_definition("dnsenum_scan")
    exec_mock = AsyncMock(return_value=("", "", None, True, 60.0))  # always times out
    decision = {
        "error_type": "timeout",
        "recovery_action": "retry_with_reduced_scope",
        "should_retry": True,
        "alternative_tool": None,
        "backoff_seconds": 0.0,
        "rebuilt_command": None,  # no-op: real_retry_decision falls back to the same command
    }

    with (
        patch.object(client, "_exec_docker_once", exec_mock),
        patch("osprey.services.execution_recovery.real_retry_decision", return_value=decision),
    ):
        response = asyncio.run(client._call_via_docker_exec(
            "dnsenum_scan", tool_def, {"domain": "slow-target.test"}, timeout=60,
            prebuilt_command="dnsenum --enum slow-target.test --noreverse --threads 20",
        ))

    assert exec_mock.await_count == 1, (
        "a timed-out command that the recovery engine couldn't actually change "
        "must not be retried — it will only time out again identically"
    )
    assert response.success is False
    assert response.timed_out is True
    assert response.recovery_info["final_action"] == "retry_skipped_identical_after_timeout"


def test_a_genuinely_different_rebuilt_command_still_retries():
    client = mcp_client.MCPClient()
    tool_def = get_tool_definition("gobuster_scan")
    exec_mock = AsyncMock(side_effect=[
        ("", "", None, True, 60.0),  # first attempt times out
        ("ok output", "", 0, False, 1.5),  # retry with the adjusted command succeeds
    ])
    decisions = [
        {
            "error_type": "timeout",
            "recovery_action": "retry_with_reduced_scope",
            "should_retry": True,
            "alternative_tool": None,
            "backoff_seconds": 0.0,
            "rebuilt_command": "gobuster dns -d slow-target.test -t 10",  # genuinely changed
        },
    ]

    with (
        patch.object(client, "_exec_docker_once", exec_mock),
        patch("osprey.services.execution_recovery.real_retry_decision", side_effect=decisions),
    ):
        response = asyncio.run(client._call_via_docker_exec(
            "gobuster_scan", tool_def, {"target": "slow-target.test"}, timeout=60,
            prebuilt_command="gobuster dns -d slow-target.test -t 50",
        ))

    assert exec_mock.await_count == 2, "a retry that actually changes the command should still run"
    assert response.success is True
