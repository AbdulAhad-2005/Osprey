"""Architecture guards for the harness-owned investigation protocol."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_old_autonomous_expansion_roots_are_deleted() -> None:
    assert not (ROOT / "backend/src/osprey/services/investigation_director.py").exists()
    assert not (ROOT / "backend/src/osprey/services/planner.py").exists()
    assert not (ROOT / "backend/src/osprey/schemas/planner.py").exists()
    assert not (ROOT / "backend/src/osprey/api/v1/endpoints/surface.py").exists()

    jobs = (ROOT / "backend/src/osprey/schemas/jobs.py").read_text(encoding="utf-8")
    mcp = (ROOT / "platform-mcp/server.py").read_text(encoding="utf-8")
    assert 'EXPANSION = "expansion"' not in jobs
    assert "def platform_expand(" not in mcp


def test_step_contract_is_revisioned_and_uses_typed_subject_ids() -> None:
    schema = (ROOT / "backend/src/osprey/schemas/investigation.py").read_text(
        encoding="utf-8"
    )
    endpoint = (
        ROOT / "backend/src/osprey/api/v1/endpoints/investigation.py"
    ).read_text(encoding="utf-8")

    assert "expected_revision" in schema
    assert "asset_id" in schema
    assert "priority_factors" in schema
    assert "stale_investigation_revision" in endpoint
    assert "subject.asset_id" in endpoint
    assert "async def start_step" in endpoint


def test_cli_and_external_harness_share_the_same_step_api() -> None:
    client = (ROOT / "cli/api/client.py").read_text(encoding="utf-8")
    mcp = (ROOT / "platform-mcp/server.py").read_text(encoding="utf-8")

    assert '"/api/v1/investigation/step"' in client
    assert '"/api/v1/investigation/step"' in mcp
    assert "platform_investigation_step" in mcp
    assert "platform_investigation_execute" in mcp
