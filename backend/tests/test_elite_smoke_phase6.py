"""Phase 6 smoke — elite suite still green; no new hard LLM cages."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.services.ingest_promoter import reload_ingest_rules, _load_rules
from pentest_platform.services.parallelism_config import max_running_jobs, reload_parallelism
from pentest_platform.services.finalize_rules import load_finalize_rules, reload_finalize_rules


def test_yaml_configs_load_wide() -> None:
    reload_ingest_rules()
    reload_parallelism()
    reload_finalize_rules()
    rules = _load_rules()
    assert len(rules) >= 15  # phase-3 expansion still present
    assert max_running_jobs() >= 1
    cfg = load_finalize_rules()
    # Soft by default — do not trap COMPLETE on hypothesis links alone
    assert cfg.get("block_hypothesis_only_paths") is False


def test_domain_hunter_is_files_not_submodule() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    assert not (root / ".gitmodules").exists()
    assert (root / "mcp-servers" / "recon" / "tools" / "domain_hunter.py").is_file()


def test_health_and_context_smoke() -> None:
    with TestClient(app) as client:
        h = client.get("/health")
        assert h.status_code == 200
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "smoke-p6.test", "name": "p6"},
        ).json()
        eid = eng["id"]
        ctx = client.get(
            "/api/v1/hybrid/context/auto",
            params={"engagement_id": eid},
        ).json()
        assert "jobs_line" in ctx
        assert "open_loops" in ctx
        outline = client.get(
            "/api/v1/hybrid/report-outline",
            params={"engagement_id": eid},
        ).json()
        assert "sections" in outline
        ready = client.get(
            "/api/v1/hybrid/finalize-readiness",
            params={"engagement_id": eid},
        ).json()
        assert "blocked_by" in ready
        assert "soft_warnings" in ready or "checks" in ready
