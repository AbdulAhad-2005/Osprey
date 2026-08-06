"""Component 1 durable evidence store — shadow observations, backfill, flip-threshold count."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.services.recovery_observation_store import get_recovery_observation_store


def _make_engagement(client: TestClient, target: str) -> str:
    resp = client.post("/api/v1/engagements/", json={"target": target, "name": "recovery-obs-test"})
    return resp.json()["id"]


def test_record_and_list_for_engagement() -> None:
    with TestClient(app) as client:
        eid = _make_engagement(client, "recoveryobs1.test")
        store = get_recovery_observation_store()
        obs = store.record(
            engagement_id=eid,
            tool_name="nmap_service_scan",
            error_type="timeout",
            asset="recoveryobs1.test",
            exit_code=124,
            shadow_strategy="retry_with_backoff",
        )
        assert obs is not None
        assert obs.error_type == "timeout"
        assert obs.llm_subsequent_tool is None

        rows = store.list_for_engagement(eid)
        assert len(rows) == 1
        assert rows[0].tool_name == "nmap_service_scan"


def test_backfill_resolves_the_most_recent_unresolved_observation() -> None:
    with TestClient(app) as client:
        eid = _make_engagement(client, "recoveryobs2.test")
        store = get_recovery_observation_store()
        store.record(
            engagement_id=eid,
            tool_name="nmap_service_scan",
            error_type="timeout",
            asset="recoveryobs2.test",
            exit_code=124,
        )
        store.backfill_subsequent_action(
            engagement_id=eid,
            asset="recoveryobs2.test",
            subsequent_tool="nmap_service_scan",
            subsequent_success=True,
        )
        rows = store.list_for_engagement(eid)
        assert rows[0].llm_subsequent_tool == "nmap_service_scan"
        assert rows[0].llm_subsequent_success is True
        assert rows[0].resolved_at is not None


def test_backfill_is_a_noop_when_nothing_unresolved_exists() -> None:
    with TestClient(app) as client:
        eid = _make_engagement(client, "recoveryobs3.test")
        store = get_recovery_observation_store()
        # No prior observation recorded — must not raise, must not create anything.
        store.backfill_subsequent_action(
            engagement_id=eid,
            asset="recoveryobs3.test",
            subsequent_tool="naabu_port_scan",
            subsequent_success=True,
        )
        assert store.list_for_engagement(eid) == []


def test_clean_observation_count_excludes_same_tool_immediate_success() -> None:
    # clean_observation_count is deliberately GLOBAL (cross-engagement, by
    # design — the flip-threshold decision needs evidence across the whole
    # tool, not one engagement). That means this test must measure its own
    # DELTA, not assert an absolute count: this suite runs against a real,
    # persistent Postgres container (docker compose exec backend pytest),
    # not the isolated in-memory SQLite conftest.py path, so rows genuinely
    # accumulate across repeated test invocations — asserting a clean-slate
    # absolute value here would be testing test-isolation, not the filter.
    with TestClient(app) as client:
        eid = _make_engagement(client, "recoveryobs4.test")
        store = get_recovery_observation_store()
        # Use per-run-unique tool names so this test's rows are unambiguously
        # its own, regardless of what accumulated from prior runs.
        fp_tool = f"whois_lookup_fp_{eid}"
        clean_tool = f"whois_lookup_clean_{eid}"

        # A false positive: classifier flagged a failure, but the LLM retried
        # the SAME tool right after and it just worked — the call was never
        # actually broken. Must NOT count as a clean observation.
        store.record(
            engagement_id=eid,
            tool_name=fp_tool,
            error_type="timeout",
            asset="fp.test",
            exit_code=124,
        )
        store.backfill_subsequent_action(
            engagement_id=eid,
            asset="fp.test",
            subsequent_tool=fp_tool,
            subsequent_success=True,
        )
        assert store.clean_observation_count(tool_name=fp_tool, error_type="timeout") == 0

        # A genuine observation: LLM switched tools after the failure —
        # consistent with the classifier's call being right. Counts as clean.
        store.record(
            engagement_id=eid,
            tool_name=clean_tool,
            error_type="timeout",
            asset="clean.test",
            exit_code=124,
        )
        store.backfill_subsequent_action(
            engagement_id=eid,
            asset="clean.test",
            subsequent_tool="dnsx_resolve",
            subsequent_success=True,
        )
        assert store.clean_observation_count(tool_name=clean_tool, error_type="timeout") == 1
