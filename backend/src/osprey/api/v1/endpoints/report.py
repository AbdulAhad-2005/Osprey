from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

router = APIRouter()


@router.get("/{engagement_id}", summary="Canonical structured engagement report")
def get_report(engagement_id: str) -> dict[str, Any]:
    """The one report structure — executive summary + risk, scope/RoE,
    methodology, findings (with evidence + remediation), unverified scanner
    claims, and the recon appendix — assembled from a single source so the GUI
    render and every export agree."""
    from osprey.services.report_builder import build_report

    report = build_report(engagement_id)
    if "error" in report:
        raise HTTPException(404, detail=report["error"])
    return report


@router.get("/{engagement_id}/markdown", response_class=PlainTextResponse, summary="Report as Markdown")
def get_report_markdown(engagement_id: str) -> PlainTextResponse:
    from osprey.services.report_builder import build_report, render_markdown

    md = render_markdown(get_report(engagement_id))
    return PlainTextResponse(md, media_type="text/markdown")
