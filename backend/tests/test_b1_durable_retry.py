"""B1 — the failure cap is durable (survives restart) and distinguishes a
genuine failure from a transient restart interruption."""

from __future__ import annotations

from osprey.services.scan_run_store import get_scan_run_store


def _failed_step(eid: str, job_id: str, oid: str, *, status: str, success=None, error: str = ""):
    get_scan_run_store().upsert(
        job_id=job_id,
        engagement_id=eid,
        kind="investigation_step",
        status=status,
        request={"opportunity_id": oid},
        result={"success": success} if success is not None else None,
        error=error,
    )


def test_durable_failed_ids_caps_after_two_genuine_failures():
    eid = "b1-durable.test"
    store = get_scan_run_store()
    # One failure — not yet capped.
    _failed_step(eid, "j1", "opp-A", status="completed", success=False)
    assert store.failed_investigation_opportunity_ids(eid, min_failures=2) == set()
    # Second failure of the SAME opportunity — now capped.
    _failed_step(eid, "j2", "opp-A", status="failed", error="tool crashed")
    assert "opp-A" in store.failed_investigation_opportunity_ids(eid, min_failures=2)


def test_restart_interrupted_run_is_not_counted_as_failure():
    eid = "b1-restart.test"
    store = get_scan_run_store()
    _failed_step(eid, "r1", "opp-B", status="failed",
                 error="Interrupted: the backend restarted while this job was still active")
    _failed_step(eid, "r2", "opp-B", status="failed",
                 error="Interrupted: the backend restarted while this job was still active")
    # Two restart interruptions must NOT cap — the opportunity never really ran.
    assert "opp-B" not in store.failed_investigation_opportunity_ids(eid, min_failures=2)


def test_successful_step_is_not_counted_as_failure():
    eid = "b1-success.test"
    store = get_scan_run_store()
    _failed_step(eid, "s1", "opp-C", status="completed", success=True)
    _failed_step(eid, "s2", "opp-C", status="completed", success=True)
    assert "opp-C" not in store.failed_investigation_opportunity_ids(eid, min_failures=2)


def test_context_packet_digest_lists_empty_attempts():
    from osprey.services.context_packet import _recently_tried_empty

    eid = "b1-digest.test"
    _failed_step(eid, "d1", "opp-D", status="completed", success=False, error="crt.sh returned 502")
    digest = _recently_tried_empty(eid)
    assert "502" in digest or "opp" in digest.lower() or "investigation_step" in digest
