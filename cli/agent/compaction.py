"""Context management for the CLI agent loop — model-aware, durable-memory-first.

The CLI's context pressure is **tool-output volume, not conversation length**:
recon tools (nmap, ffuf, nuclei, gau/katana, subfinder) emit large blobs that
fill the window in a handful of calls. Osprey already writes the *full* output to
the server-side artifact store and the extracted facts to the findings graph, so
the conversation is a working buffer, not the source of truth. That lets us manage
context non-destructively:

  Tier 1 — spill (no LLM): cap each tool result going INTO history; keep a
           head/tail preview + a pointer to the durable copy. Nothing is lost —
           full output is in platform_artifact, findings in platform_findings.
  Tier 2 — compact (one LLM call): when the running prompt approaches the model's
           real context window, summarize the older whole-turns into one rolling
           checkpoint and keep the recent tail verbatim. Never split a
           tool-call/result pair; never touch the system prompt.

Everything here is pure/near-pure and unit-testable without a live model. The one
model call (the summary itself) is made by the caller via ``complete``; this module
only decides *what* to summarize and *how* to frame it.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Rough chars/token when no real tokenizer is reachable. Deliberately low
# (pessimistic) so an estimate errs toward compacting a little early rather than
# overflowing the provider.
_CHARS_PER_TOKEN = 4

# Conservative fallback window for a model litellm doesn't know. Small enough to
# be safe on an unknown small model; override with LLM_CONTEXT_TOKENS for a big one.
_FALLBACK_CONTEXT_TOKENS = 32_768

# Per-tool-result cap in CHARS before we spill to a pointer (~1.5k tokens of
# head+tail preview). The full output is always still retrievable server-side.
_DEFAULT_SPILL_CHARS = 6_000
_SPILL_HEAD_CHARS = 2_800
_SPILL_TAIL_CHARS = 2_400


@dataclass(frozen=True)
class ContextBudget:
    """Resolved token budget for one session/model."""

    context_limit: int          # the model's usable input window (tokens)
    reserve: int                # output headroom kept free for the completion
    compact_at: int             # prompt-token level that triggers compaction
    keep_recent_tokens: int     # verbatim tail preserved through a compaction

    @property
    def usable(self) -> int:
        return max(self.context_limit - self.reserve, 1)


def resolve_context_limit(model: str) -> int:
    """The model's real input window in tokens.

    Precedence: explicit LLM_CONTEXT_TOKENS env override → litellm's model
    registry → a conservative fallback. Never raises — an unknown model must
    degrade to safe-but-small, not crash the session.
    """
    override = (os.getenv("LLM_CONTEXT_TOKENS") or "").strip()
    if override:
        try:
            val = int(override)
            if val > 0:
                return val
        except ValueError:
            pass
    try:
        import litellm

        info = litellm.get_model_info(model) or {}
        limit = info.get("max_input_tokens") or info.get("max_tokens")
        if isinstance(limit, int) and limit > 0:
            return limit
    except Exception as exc:  # noqa: BLE001 — unknown model / offline registry
        logger.debug("model info unavailable for %s: %s", model, exc)
    return _FALLBACK_CONTEXT_TOKENS


def resolve_output_reserve(model: str, requested_max_tokens: int) -> int:
    """Tokens to hold back for the completion so we compact BEFORE the provider
    would reject. At least the completion's own max_tokens plus a margin."""
    margin = 1_024
    reserve = max(int(requested_max_tokens or 0), 2_048) + margin
    try:
        import litellm

        info = litellm.get_model_info(model) or {}
        max_out = info.get("max_output_tokens")
        if isinstance(max_out, int) and max_out > 0:
            reserve = max(reserve, min(max_out, 8_192) + margin)
    except Exception:  # noqa: BLE001
        pass
    return reserve


def build_budget(
    model: str,
    *,
    requested_max_tokens: int,
    tpm_budget_tokens: int = 0,
    trigger_ratio: float = 0.8,
) -> ContextBudget:
    """Resolve the full budget for a model.

    ``tpm_budget_tokens`` (the opt-in per-minute cap, LLM_TOOL_SCHEMA_BUDGET_TOKENS)
    is a DIFFERENT axis from the context window, but if it is set and smaller than
    the window it also bounds how much we can send per call — so the effective
    limit is the min of the two. When unset (0) only the context window applies.
    """
    context_limit = resolve_context_limit(model)
    if tpm_budget_tokens and tpm_budget_tokens > 0:
        context_limit = min(context_limit, tpm_budget_tokens)
    reserve = resolve_output_reserve(model, requested_max_tokens)
    # Keep reserve sane relative to a small window.
    reserve = min(reserve, max(context_limit // 2, 512))
    usable = max(context_limit - reserve, 1)
    compact_at = int(usable * trigger_ratio)
    keep_recent_tokens = _clamp(usable // 4, 2_000, 25_000)
    return ContextBudget(
        context_limit=context_limit,
        reserve=reserve,
        compact_at=compact_at,
        keep_recent_tokens=keep_recent_tokens,
    )


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(value, high))


def estimate_tokens(text: str) -> int:
    return max(len(text) // _CHARS_PER_TOKEN, 1)


def count_message_tokens(model: str, messages: list[dict[str, Any]]) -> int:
    """Accurate token count when litellm can tokenize for the model; a cheap
    char/4 estimate otherwise. Never raises."""
    try:
        import litellm

        return int(litellm.token_counter(model=model, messages=messages))
    except Exception as exc:  # noqa: BLE001
        logger.debug("token_counter unavailable for %s: %s", model, exc)
        return sum(estimate_tokens(str(m.get("content") or "")) + 4 for m in messages)


# ---------------------------------------------------------------------------
# Tier 1 — tool-output spill
# ---------------------------------------------------------------------------

def spill_tool_result(
    result: str,
    *,
    engagement_id: str = "",
    max_chars: int = _DEFAULT_SPILL_CHARS,
) -> str:
    """Cap a tool result destined for history. If it's larger than ``max_chars``,
    keep a head+tail preview and append a pointer to the durable copy. Returns the
    result unchanged when it already fits.

    This is non-destructive: the full stdout is already saved server-side
    (platform_artifact / stdout index) and any parsed facts are already typed
    findings in the graph — so the model loses nothing it can't retrieve on demand.
    """
    if len(result) <= max_chars:
        return result
    omitted = len(result) - (_SPILL_HEAD_CHARS + _SPILL_TAIL_CHARS)
    head = result[:_SPILL_HEAD_CHARS]
    tail = result[-_SPILL_TAIL_CHARS:]
    eid = f" (engagement_id={engagement_id})" if engagement_id else ""
    pointer = (
        f"\n\n… [{omitted} chars trimmed to protect context. The FULL output is "
        f"saved server-side — retrieve it with platform_artifact or search it with "
        f"platform_memory_search{eid}; any facts it contained are already typed "
        f"findings in platform_findings. Re-run the tool only if you truly need the "
        f"raw bytes again.] …\n\n"
    )
    return f"{head}{pointer}{tail}"


# ---------------------------------------------------------------------------
# Tier 2 — turn-safe compaction planning
# ---------------------------------------------------------------------------

def split_into_turns(messages: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group non-system messages into whole turns. A turn starts at a ``user``
    message and runs up to (but not including) the next ``user`` message — so an
    assistant message carrying tool_calls always stays with the ``tool`` result
    messages that answer it. Splitting on any other boundary produces an invalid
    request on every OpenAI-compatible API."""
    turns: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for msg in messages:
        if msg.get("role") == "user" and current:
            turns.append(current)
            current = []
        current.append(msg)
    if current:
        turns.append(current)
    return turns


@dataclass
class CompactionPlan:
    system: list[dict[str, Any]]
    head: list[dict[str, Any]]          # whole turns to summarize (oldest)
    tail: list[dict[str, Any]]          # whole turns kept verbatim (newest)

    @property
    def has_head(self) -> bool:
        return bool(self.head)


def plan_compaction(
    model: str,
    messages: list[dict[str, Any]],
    budget: ContextBudget,
) -> CompactionPlan:
    """Decide which whole-turns to summarize vs keep verbatim.

    Walks newest→oldest accumulating token estimates until ``keep_recent_tokens``
    is met; everything older becomes the head to summarize. The most recent turn
    is always kept whole. System messages are always preserved and never counted
    against the tail budget."""
    system = [m for m in messages if m.get("role") == "system"]
    rest = [m for m in messages if m.get("role") != "system"]
    turns = split_into_turns(rest)
    if len(turns) <= 1:
        return CompactionPlan(system=system, head=[], tail=rest)

    kept: list[list[dict[str, Any]]] = []
    total = 0
    for turn in reversed(turns):
        size = count_message_tokens(model, turn)
        if kept and total + size > budget.keep_recent_tokens:
            break
        kept.append(turn)
        total += size
    kept.reverse()
    head_turns = turns[: len(turns) - len(kept)]
    head = [m for turn in head_turns for m in turn]
    tail = [m for turn in kept for m in turn]
    return CompactionPlan(system=system, head=head, tail=tail)


# ---------------------------------------------------------------------------
# Summary framing
# ---------------------------------------------------------------------------

# Pentest-flavored rolling checkpoint (adapted from the OpenCode/deepseek-harness
# section template — Objective/Details/State/Next — retargeted to an engagement).
_SUMMARY_SYSTEM = """\
You are compacting the earlier part of an ongoing authorized-pentest session to
save context. Produce a TERSE checkpoint under these exact headings, preserving
every operationally load-bearing detail (exact hosts, IPs, ports, URLs,
technologies, credentials/secrets seen, payloads that worked, and tool+params
already run so they are not repeated). Do NOT invent, do NOT soften severities,
do NOT mention that compaction happened.

## Target & Scope
## Confirmed Findings (with evidence)
## Attack Surface Mapped (hosts/ports/services/tech)
## Current Foothold / In-Progress
## Ruled Out / Dead Ends
## Next Moves
## Evidence Pointers (artifact ids / finding refs)

Keep it factual and dense; bullets over prose. If a prior checkpoint is provided,
UPDATE it (merge new facts, drop nothing still relevant) rather than restating."""


def serialize_history(messages: list[dict[str, Any]]) -> str:
    """Flatten a run of messages to plain text for the summarizer."""
    lines: list[str] = []
    for m in messages:
        role = str(m.get("role") or "?")
        content = str(m.get("content") or "").strip()
        tool_calls = m.get("tool_calls") or []
        if tool_calls:
            names = ", ".join(
                f"{tc.get('function', {}).get('name', '?')}({tc.get('function', {}).get('arguments', '')[:200]})"
                for tc in tool_calls
            )
            lines.append(f"[{role} tool_calls] {names}")
        if content:
            lines.append(f"[{role}] {content}")
    return "\n".join(lines)


def build_summary_request(
    head: list[dict[str, Any]],
    *,
    previous_summary: str = "",
) -> list[dict[str, Any]]:
    """Messages for the one summarization completion (no tools)."""
    prior = f"\n\nPRIOR CHECKPOINT TO UPDATE:\n{previous_summary}" if previous_summary else ""
    body = serialize_history(head)
    return [
        {"role": "system", "content": _SUMMARY_SYSTEM},
        {
            "role": "user",
            "content": f"Compact this earlier session segment into the checkpoint.{prior}\n\nSEGMENT:\n{body}",
        },
    ]


def checkpoint_message(summary: str) -> dict[str, Any]:
    """How the rolling checkpoint re-enters history: a plain user turn the model
    reads as established context, placed right after the system prompt and before
    the verbatim tail."""
    return {
        "role": "user",
        "content": (
            "[CONTEXT CHECKPOINT — earlier turns were summarized to save space. "
            "Treat the following as established engagement state; the full record "
            "is in durable memory (platform_findings / platform_artifact).]\n\n"
            + summary
        ),
    }
