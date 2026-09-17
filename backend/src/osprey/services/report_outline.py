"""Report outline from memory — Confirmed / Likely / Hypotheses.

Helps the LLM structure a trusted report without a hardcoded narrative.
"""

from __future__ import annotations

from typing import Any

from osprey.services.findings_store import get_findings_store
from osprey.services.phase_supervisor import (
    phase_readiness_snapshot,
    phase_readiness_text,
)

_OUTLINE_PER_SECTION = 25


def _confidence(f: Any) -> str:
    c = getattr(f, "confidence", None)
    if hasattr(c, "value"):
        return str(c.value)
    return str(c or "likely").lower()


def _line(f: Any) -> str:
    sev = getattr(f, "claim_severity", None)
    sev_s = getattr(sev, "value", sev) or "none"
    parents = (f.metadata or {}).get("derived_from") or []
    parent_bit = f" ←{','.join(str(p) for p in parents[:4])}" if parents else ""
    return (
        f"[{_confidence(f)}|{sev_s}] {f.title[:140]} "
        f"(id={f.id} via {f.source_tool or '?'}){parent_bit}"
    )


def build_report_outline(
    engagement_id: str,
    *,
    run_id: str = "",
) -> dict[str, Any]:
    eid = (engagement_id or "").strip()
    if not eid:
        return {
            "engagement_id": "",
            "sections": {},
            "text": "Bind a target first.",
            "note": "No engagement.",
        }

    cap = _OUTLINE_PER_SECTION
    findings = get_findings_store().list(engagement_id=eid, run_id=run_id or None, limit=5000)

    confirmed: list[str] = []
    likely: list[str] = []
    hypotheses: list[str] = []
    sev_counts: dict[str, int] = {"none": 0, "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        tags = {str(t).lower() for t in (f.tags or [])}
        conf = _confidence(f)
        sev_str = str(getattr(getattr(f, "claim_severity", None), "value", getattr(f, "claim_severity", "none")) or "none").lower()
        sev_counts[sev_str] = sev_counts.get(sev_str, 0) + 1
        line = _line(f)
        if (
            conf == "hypothesis"
            or "hypothesis" in tags
            or (f.title or "").startswith("HYPOTHESIS")
            or "operator_think" in tags
            or any(str(t).startswith("rel:hypothesis") for t in tags)
        ):
            hypotheses.append(line)
        elif conf == "confirmed":
            confirmed.append(line)
        else:
            likely.append(line)

    readiness = phase_readiness_snapshot(eid, run_id=run_id)
    readiness_line = phase_readiness_text(readiness)

    sections = {
        "confirmed": confirmed[-cap:],
        "likely": likely[-cap:],
        "hypotheses": hypotheses[-cap:],
        "phase_readiness": readiness,
    }

    parts = [
        "## Report outline (from memory — not chat recollection)",
        f"### Severity breakdown: critical={sev_counts['critical']} high={sev_counts['high']} "
        f"medium={sev_counts['medium']} low={sev_counts['low']} info={sev_counts['info']}",
        f"### 1. Confirmed — {len(confirmed)}",
        "\n".join(f"- {x}" for x in sections["confirmed"]) or "- (none)",
        f"### 2. Likely — {len(likely)}",
        "\n".join(f"- {x}" for x in sections["likely"]) or "- (none)",
        f"### 3. Hypotheses — {len(hypotheses)}",
        "\n".join(f"- {x}" for x in sections["hypotheses"]) or "- (none)",
        "### Phase status (conductor)",
        readiness_line,
        "",
        "Anti-hype: never promote hypothesis/likely to CRITICAL without real proof "
        "(data extracted, shell, validated credential). Quote confirmed rows with "
        "evidence — platform_artifact for raw stdout.",
    ]
    return {
        "engagement_id": eid,
        "counts": {
            "confirmed": len(confirmed),
            "likely": len(likely),
            "hypotheses": len(hypotheses),
            "severity": sev_counts,
        },
        "sections": sections,
        "text": "\n".join(parts),
        "note": (
            "Structure only — you write the prose. derived_from chains show as ←ids."
        ),
    }
