"""Parsers for the deterministic-verification primitives (canary_confirm,
response_diff_confirm) — plans/harness/12-deterministic-evidence-
verification.md Step 2.

Each tool's own JSON stdout IS the raw evidence — a byte-for-byte fact the
tool checked itself, not a claim. Stashing it verbatim in details["snippet"]
is what lets a later platform_file_finding(evidence_kind="reproduction")
citing this observation pass evidence_grounding.py's check by quoting a real
`context`/`diff` excerpt straight out of it.

A positive result (the canary reflected; the two responses differ) becomes a
SCANNER_SIGNAL — "may be a vuln, not yet judged", same bucket every other
scanner-signal tool feeds into — a claim a brain judges via file_finding. A
clean negative (no reflection; identical responses) is still recorded as RAW
— a negative result run through this deterministic check is itself useful
evidence (a claim that WOULD have shown up here and didn't), never silently
dropped.
"""

from __future__ import annotations

import json

from osprey.schemas.observation import Observation, ObservationType


def _load(stdout: str) -> dict | None:
    text = (stdout or "").strip()
    start = text.find("{")
    if start == -1:
        return None
    try:
        data = json.loads(text[start:])
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def parse_canary_confirm(stdout, *, engagement_id="", run_id="", target=""):
    data = _load(stdout)
    if data is None:
        return []
    url = str(data.get("url") or target)
    found = bool(data.get("found"))
    obs_type = ObservationType.SCANNER_SIGNAL if found else ObservationType.RAW
    tags = ["canary_confirm", "deterministic"]
    if found:
        tags.append("reflected")
    return [Observation(
        engagement_id=engagement_id, run_id=run_id,
        type=obs_type,
        target=url, source_tool="canary_confirm",
        details={
            "title": f"Canary token reflected at {url}" if found else f"Canary not reflected at {url}",
            "claimed_severity": "medium" if found else "none",
            "canary": str(data.get("canary") or ""),
            "found": found,
            "occurrences": data.get("occurrences"),
            "context": str(data.get("context") or ""),
            "status_code": data.get("status_code"),
            # The tool's own raw JSON — the substrate evidence_grounding.py
            # checks a later reproduction claim against.
            "snippet": (stdout or "").strip()[:8000],
        },
        tags=tags,
    )]


def parse_response_diff_confirm(stdout, *, engagement_id="", run_id="", target=""):
    data = _load(stdout)
    if data is None:
        return []
    url_a = str(data.get("url_a") or target)
    identical = data.get("identical")
    differs = identical is False
    obs_type = ObservationType.SCANNER_SIGNAL if differs else ObservationType.RAW
    tags = ["response_diff_confirm", "deterministic"]
    if differs:
        tags.append("differential")
    title = (
        f"Response differential confirmed between {data.get('url_a')} and {data.get('url_b')}"
        if differs else f"No response differential between {data.get('url_a')} and {data.get('url_b')}"
    )
    return [Observation(
        engagement_id=engagement_id, run_id=run_id,
        type=obs_type,
        target=url_a, source_tool="response_diff_confirm",
        details={
            "title": title,
            "claimed_severity": "medium" if differs else "none",
            "identical": identical,
            "status_code_a": data.get("status_code_a"),
            "status_code_b": data.get("status_code_b"),
            "length_delta": data.get("length_delta"),
            "diff": data.get("diff") or [],
            "snippet": (stdout or "").strip()[:8000],
        },
        tags=tags,
    )]


def _register_deterministic_confirm_parsers() -> None:
    from osprey.services.parsers.registry import register_output_parser

    register_output_parser("canary_confirm", parse_canary_confirm)
    register_output_parser("response_diff_confirm", parse_response_diff_confirm)


_register_deterministic_confirm_parsers()
