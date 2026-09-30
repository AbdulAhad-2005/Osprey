"""_JobRecord.tool_name for kind=investigation_step used to always synthesize
"investigation:<capability>", even though the opportunity's real tool
(Plan 17/18: every opportunity is exactly one real tool call) was sitting
right there on the request. This hid which tool was actually running from
anything that reads JobSummary.tool_name — including a resumed/reattached
CLI investigation loop, which had no way to show a real tool-call card for
a job it didn't itself just start.
"""

from __future__ import annotations

from osprey.schemas.jobs import JobKind, JobStartRequest
from osprey.services.job_store import _JobRecord


def test_investigation_step_tool_name_is_the_real_tool_when_present():
    req = JobStartRequest(
        kind=JobKind.INVESTIGATION_STEP, engagement_id="e1",
        capability="discover_related_domains", tool="crt_sh_query",
        opportunity_id="opp-1", subject_ids=["dom:example.test"],
    )
    rec = _JobRecord(req)
    assert rec.tool_name == "crt_sh_query"


def test_investigation_step_tool_name_falls_back_for_analytical_kinds():
    """promote_observations/detect_anomalies/etc. carry no tool at all —
    the synthetic label is the only meaningful name available for those."""
    req = JobStartRequest(
        kind=JobKind.INVESTIGATION_STEP, engagement_id="e1",
        capability="detect_anomalies", tool="",
        opportunity_id="opp-2", subject_ids=["dom:example.test"],
    )
    rec = _JobRecord(req)
    assert rec.tool_name == "investigation:detect_anomalies"


def test_explicit_label_still_wins_over_synthesized_tool_name():
    req = JobStartRequest(
        kind=JobKind.INVESTIGATION_STEP, engagement_id="e1",
        capability="discover_related_domains", tool="crt_sh_query",
        tool_name="operator-override", opportunity_id="opp-3", subject_ids=["dom:example.test"],
    )
    rec = _JobRecord(req)
    assert rec.tool_name == "operator-override"
