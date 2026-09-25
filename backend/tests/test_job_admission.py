from __future__ import annotations

import pytest
from osprey.schemas.jobs import JobKind, JobStartRequest
from osprey.services.job_store import JobStore


def test_job_without_event_loop_does_not_leave_phantom_record() -> None:
    store = JobStore()
    request = JobStartRequest(
        kind=JobKind.TOOL,
        engagement_id="eng_no_loop",
        tool_name="httpx_probe",
        params={"target": "example.test"},
    )

    with pytest.raises(ValueError, match="async server event loop"):
        store.create_and_spawn(request)

    assert store.list_for_engagement("eng_no_loop") == []
