"""Job ids are now tool-named ("job_nmap_service_scan1") instead of an
opaque uuid blob — regression coverage for _JobRecord's id numbering."""

from __future__ import annotations

from osprey.schemas.jobs import JobKind, JobStartRequest
from osprey.services.job_store import _JobRecord


def test_first_job_for_a_tool_gets_number_one():
    req = JobStartRequest(kind=JobKind.TOOL, engagement_id="e1", tool_name="nmap_service_scan")
    rec = _JobRecord(req)
    assert rec.job_id == "job_nmap_service_scan1"


def test_repeat_tool_increments_against_siblings():
    req1 = JobStartRequest(kind=JobKind.TOOL, engagement_id="e1", tool_name="httpx_probe")
    rec1 = _JobRecord(req1)
    req2 = JobStartRequest(kind=JobKind.TOOL, engagement_id="e1", tool_name="httpx_probe")
    rec2 = _JobRecord(req2, existing={rec1.job_id: rec1})
    assert rec1.job_id == "job_httpx_probe1"
    assert rec2.job_id == "job_httpx_probe2"


def test_investigation_step_uses_the_real_tool_for_the_id():
    req = JobStartRequest(
        kind=JobKind.INVESTIGATION_STEP, engagement_id="e1",
        capability="discover_related_domains", tool="crt_sh_query",
        opportunity_id="opp-1", subject_ids=["dom:example.test"],
    )
    rec = _JobRecord(req)
    assert rec.job_id == "job_crt_sh_query1"


def test_different_tools_dont_collide_on_number():
    req_a = JobStartRequest(kind=JobKind.TOOL, engagement_id="e1", tool_name="amass_scan")
    rec_a = _JobRecord(req_a)
    req_b = JobStartRequest(kind=JobKind.TOOL, engagement_id="e1", tool_name="dnsenum_scan")
    rec_b = _JobRecord(req_b, existing={rec_a.job_id: rec_a})
    assert rec_a.job_id == "job_amass_scan1"
    assert rec_b.job_id == "job_dnsenum_scan1"
