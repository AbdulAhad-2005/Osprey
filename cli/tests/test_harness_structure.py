from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_http_client_contains_no_harness_state() -> None:
    source = (ROOT / "cli" / "api" / "client.py").read_text(encoding="utf-8")
    for forbidden in (
        "agent_runner",
        "agent_loop",
        "active_agent",
        "_engagement_id",
        "_engagement_target",
        "_set_active_engagement",
    ):
        assert forbidden not in source


def test_runner_does_not_own_gateway_or_worker_construction() -> None:
    source = (ROOT / "cli" / "agent" / "loop.py").read_text(encoding="utf-8")
    assert "platform_tools.load_server" not in source
    assert "platform_tools.bind_session" not in source
    assert "platform_tools.current_engagement_id" not in source
    assert "worker = Runner(" not in source


def test_cli_never_reads_fastmcp_private_registry() -> None:
    for path in (ROOT / "cli").rglob("*.py"):
        if "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        assert "mcp._tool_manager" not in source, str(path)


def test_every_main_entrypoint_wraps_transport_in_runtime() -> None:
    source = (ROOT / "cli" / "main.py").read_text(encoding="utf-8")
    assert source.count("get_runtime(APIClient(") == source.count("APIClient(")


def test_cli_engine_uses_step_contract_not_expansion_workflow() -> None:
    for path in (ROOT / "cli").rglob("*.py"):
        if "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        assert "start_expansion_job" not in source, str(path)
        assert "run_expansion(" not in source, str(path)
