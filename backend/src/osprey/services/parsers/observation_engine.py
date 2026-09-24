"""Optional LLM observation extraction — plans/harness/02-evidence-and-observation-layer.md Step 5.

Replaces ``dynamic_fallback.py``. The difference is not cosmetic: the old
module asked the LLM to emit `Finding`s directly (severity, confidence, a
verdict) with no evidence layer underneath. This module asks the LLM to
extract *more structural facts* the deterministic parsers missed — the exact
same job a regex-based parser does, just for shapes nobody has written a
regex for yet. It is strictly an extractor: forbidden from assigning
severity, confidence, or stating anything is a vulnerability. Confidence is
never an LLM's to assign — see ``services/confidence.py`` (Plan 03).

Cost budget (Plan 02 Step 5, required): this only runs when deterministic
extraction found nothing (the caller in ``registry.py`` only reaches here on
an empty parse) and only for high-value/unstructured output
(``output_budget.is_high_value`` — script/shell output, tools nobody has
written a parser for). A per-engagement call budget caps runaway cost; once
hit, the deterministic RAW-observation floor is what every later empty parse
gets, same as when no LLM is configured at all.
"""

from __future__ import annotations

import json
import logging
import re
import threading

from pydantic import ValidationError

from osprey.schemas.observation import Observation, ObservationSource, ObservationType
from osprey.services.llm_service import LLMServiceError, get_llm_service, llm_configured
from osprey.services.output_budget import is_high_value

logger = logging.getLogger(__name__)

_MAX_INPUT_CHARS = 12_000
_MAX_EXTRACTED = 25
_MAX_CALLS_PER_ENGAGEMENT = 40

_OBS_TYPES = [t.value for t in ObservationType]

_SYSTEM_PROMPT = (
    "You extract structural facts from raw penetration-test tool output — "
    "ports, services, technologies, endpoints, DNS records, headers, and "
    "similar. You are a strict structural extractor, not a security analyst: "
    "report only facts the text directly states (what exists, what was "
    "observed), never a judgment about whether something is a vulnerability, "
    "how severe it is, or how confident anyone should be that it's exploitable. "
    "Never include a severity, risk, or confidence rating in your output — "
    "that is computed elsewhere, from evidence, never asserted by you. "
    "If the text has nothing extractable, return an empty list. Output ONLY "
    "a JSON array, no prose, no markdown fences."
)

_INSTRUCTIONS = (
    "Each array item must be an object with these keys:\n"
    '  "type": one of ' + json.dumps(_OBS_TYPES) + "\n"
    '  "target": the host/URL/asset this fact concerns (string)\n'
    '  "details": an object of the structural fields you found (e.g. '
    '{"port": 8443, "service": "nginx", "version": "1.24"}) — facts only, '
    "no severity/confidence/verdict keys.\n"
    "Return [] if nothing is extractable. Do not fabricate hosts, ports, or "
    "values not present in the text."
)

_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

_lock = threading.Lock()
_calls_by_engagement: dict[str, int] = {}


def _budget_remaining(engagement_id: str) -> bool:
    if not engagement_id:
        return True
    with _lock:
        return _calls_by_engagement.get(engagement_id, 0) < _MAX_CALLS_PER_ENGAGEMENT


def _record_call(engagement_id: str) -> None:
    if not engagement_id:
        return
    with _lock:
        _calls_by_engagement[engagement_id] = _calls_by_engagement.get(engagement_id, 0) + 1


def reset_budget(engagement_id: str | None = None) -> None:
    with _lock:
        if engagement_id:
            _calls_by_engagement.pop(engagement_id, None)
        else:
            _calls_by_engagement.clear()


async def extract(
    tool_name: str,
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """Best-effort: turn raw stdout into structural Observations via the
    platform LLM. Returns [] (never raises) on any failure, budget exhaustion,
    or when the output isn't worth an LLM call — callers always have the raw
    RAW-type observation to fall back to.
    """
    text = (stdout or "").strip()
    if not text or not llm_configured():
        return []
    if not is_high_value(tool_name):
        return []
    if not _budget_remaining(engagement_id):
        logger.debug("Observation-extraction budget exhausted for engagement=%s", engagement_id)
        return []

    truncated = text[:_MAX_INPUT_CHARS]
    note = (
        ""
        if len(text) <= _MAX_INPUT_CHARS
        else f"\n[...truncated, {len(text) - _MAX_INPUT_CHARS} more chars omitted]"
    )

    _record_call(engagement_id)
    try:
        llm = get_llm_service()
        response = await llm.complete(
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Tool: {tool_name}\nTarget: {target or 'unknown'}\n\n"
                        f"{_INSTRUCTIONS}\n\n--- RAW OUTPUT ---\n{truncated}{note}"
                    ),
                },
            ],
            temperature=0.0,
            max_tokens=3000,
        )
    except LLMServiceError as exc:
        logger.debug("Observation extraction unavailable for %s: %s", tool_name, exc)
        return []
    except Exception:
        logger.exception("Observation extraction errored for %s", tool_name)
        return []

    try:
        content = response["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        return []

    items = _extract_json_array(content)
    if not items:
        return []

    observations: list[Observation] = []
    for item in items[:_MAX_EXTRACTED]:
        obs = _to_observation(
            item, tool_name=tool_name, engagement_id=engagement_id, run_id=run_id, target=target
        )
        if obs is not None:
            observations.append(obs)
    return observations


def _extract_json_array(content: str) -> list | None:
    text = (content or "").strip()
    if text.startswith("```"):
        text = _FENCE_RE.sub("", text).strip()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        match = _JSON_ARRAY_RE.search(text)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            return None
    return data if isinstance(data, list) else None


def _to_observation(
    item: object,
    *,
    tool_name: str,
    engagement_id: str,
    run_id: str,
    target: str,
) -> Observation | None:
    if not isinstance(item, dict):
        return None
    try:
        otype = ObservationType(str(item.get("type") or "raw"))
    except ValueError:
        otype = ObservationType.RAW

    details = item.get("details")
    if not isinstance(details, dict):
        details = {}
    # Strip any judgment keys the model might still slip in — belt and
    # braces on top of the system prompt's instruction not to include them.
    details = {
        k: v for k, v in details.items()
        if k.lower() not in ("severity", "confidence", "claim_severity", "risk", "verdict")
    }

    item_target = str(item.get("target") or target).strip()[:512]
    try:
        return Observation(
            engagement_id=engagement_id,
            run_id=run_id,
            type=otype,
            target=item_target,
            source_tool=tool_name,
            extracted_by=ObservationSource.LLM,
            details=details,
            tags=["llm_extracted"],
        )
    except ValidationError:
        return None
