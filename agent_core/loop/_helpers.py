"""The CLI's own ReAct loop — this is what makes the CLI a real agent host
instead of a remote control.

This is the ONE reasoning loop in Osprey: build messages, call the model, run
any tool calls — concurrently, bounded — append results, repeat until the model
stops asking for tools. The CLI drives it directly, and the backend runs a
headless instance of this same `Runner` for every scoped sub-agent job
(services/agent_runner.py) — there is no separate backend-native agent loop.
It needs only `tools.py` (HTTP-only, works against a local or remote backend)
and `llm.py` (a plain third-party library), never a DB/job-store-coupled path.

One `Runner` instance lives for the whole CLI session, so a follow-up
prompt sees the full prior conversation — exactly like Claude Code's own
CLI, not a one-shot request/response.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


_MAX_TURNS = 30
_MAX_CONCURRENT_TOOLS = 4
# Output tokens requested per completion — kept in sync with the budget's output
# reserve (compaction.resolve_output_reserve) so we compact before the provider
# would reject the request.
_COMPLETION_MAX_TOKENS = 4096
# How often to report "still waiting on the provider" while a completion call
# is in flight — a genuinely overloaded provider can take several minutes
# (complete()'s own 3-attempt x up to 120s retry) to finally fail; without a
# periodic signal that's indistinguishable from a hang. See _complete_with_feedback.
_STILL_WAITING_INTERVAL = 15.0


def _is_context_overflow(exc: Exception) -> bool:
    """True when a completion failed specifically because the request exceeded the
    model's context window — the one failure a compaction-and-retry can fix."""
    try:
        import litellm

        if isinstance(exc, litellm.ContextWindowExceededError):
            return True
    except Exception:  # noqa: BLE001 — litellm import/attr issues never matter here
        pass
    text = str(exc).lower()
    return any(
        s in text
        for s in ("context length", "maximum context", "context_length_exceeded",
                  "too many tokens", "reduce the length", "context window")
    )


# --- Loop-level failure/repeat guards ------------------------------------
# Per-call recovery (param adjust, tool switch, escalation-matrix auto-fallback)
# already happens server-side inside one tool call. What the AGENT LOOP must add
# is cross-call escalation: an LLM stuck re-issuing a call that makes no progress,
# or hammering a tool that keeps failing, across turns. Neither is caught below
# the loop — this is where "escalate on repeated failure" lives.
#
# The guard keys on NON-PROGRESS (same call → same result), not merely on "same
# arguments": a poll (platform_job_poll, a platform_context refresh) is SUPPOSED
# to be called repeatedly with identical args, and its result changes as state
# advances — so it must never be blocked. Only a call whose result stops changing
# (a stuck poll, a deterministic scan re-run for no reason, a repeating failure)
# trips the guard. No tool allowlist, no special-casing — the signal is the data.
_STALL_THRESHOLD = 3           # identical (call → identical result) repeats before the next is blocked
_REPEATED_FAILURE_THRESHOLD = 3  # consecutive failures of one tool before a "stop retrying it" nudge


def _call_signature(name: str, args: dict[str, Any]) -> str:
    try:
        return name + ":" + json.dumps(args or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return name + ":" + str(sorted((args or {}).items()))


def _result_fingerprint(result: str) -> str:
    """Cheap, stable identity of a tool result, so repeated-but-changing output
    (a poll advancing) is distinguished from genuinely non-progressing output."""
    import hashlib

    return hashlib.sha1(result.encode("utf-8", "replace")).hexdigest()


def tool_result_failed(result: str) -> bool:
    """Canonical failure signal for a tool result — the platform's own
    ``success: False`` line, or a dispatch-level ``ERROR ...`` string. Single
    source of truth shared by the loop's failure escalation and the CLI renderer
    (cli/commands/prompt.py), so the two can't drift on what 'failed' means."""
    if result.lstrip().startswith("ERROR"):
        return True
    import re

    m = re.search(r"(?im)^success:\s*(true|false)\b", result)
    if m:
        return m.group(1).lower() == "false"
    # Dispatch errors can have an operator-mirror heading. Inspect the header,
    # not stdout (which may legitimately contain an error string as evidence).
    header = result.split("```", 1)[0]
    return bool(re.search(r"(?m)^ERROR:", header))


def refresh_system_message(messages: list[dict[str, Any]], system_prompt: str) -> list[dict[str, Any]]:
    """Replace the current system message with a fresh one, or insert it if
    there isn't one yet — plans/harness/07-context-packet.md Step 2/4. A pure
    function (no I/O) so the "rebuild every turn, including across
    compaction" behavior is directly testable without mocking the LLM/tool
    machinery ``Runner.run()`` also needs. Mutates and returns ``messages``
    for convenience; empty ``system_prompt`` is a no-op (keeps whatever's
    already there unchanged)."""
    if not system_prompt:
        return messages
    fresh = {"role": "system", "content": system_prompt}
    if messages and messages[0].get("role") == "system":
        messages[0] = fresh
    else:
        messages.insert(0, fresh)
    return messages


def _stall_notice(name: str, count: int) -> str:
    return (
        f"BLOCKED (no-progress guard): {name} returned the same result {count} times "
        f"in a row for this input — re-running it is not advancing the engagement. "
        f"Change the arguments or approach, try a different tool, or record this as a "
        f"blocker and move on — do not repeat this exact call."
    )


def _repeated_failure_notice(name: str, count: int) -> str:
    return (
        f"\n\n[loop guard] {name} has now failed {count} times in a row. Stop "
        f"retrying it as-is — switch to an alternative tool (see any hints in the "
        f"output above) or a different technique, or report the blocker and move on."
    )

# CLI-native — not a platform tool. This is the actual fix for "spawns a
# subagent for everything": it's a real, capped tool the model has to
# deliberately reach for, with an explicit policy in its own description,
# not just advisory prompt text elsewhere that only some harnesses read.
_SPAWN_TOOL_NAME = "spawn_subagents"
_SPAWN_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": _SPAWN_TOOL_NAME,
        "description": (
            "Run 2-4 genuinely independent, parallelizable slices of work at "
            "once (e.g. one sister domain each, one unrelated host each, one "
            "candidate each) as separate concurrent workers sharing this "
            "engagement's memory. Each worker gets its own tools and reports "
            "back a short summary when done. "
            "Do NOT call this for a single line of work, for sequential steps "
            "that depend on each other, or just because a task 'sounds big' — "
            "keep working in the current turn instead. Only call this when you "
            "can name 2 or more slices that could genuinely run at the same "
            "time with no dependency between them."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tasks": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": _MAX_CONCURRENT_TOOLS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "task": {
                                "type": "string",
                                "description": "The independent slice of work for this worker, in full — it has no other context.",
                            },
                            "scope": {
                                "type": "string",
                                "description": "The specific target/host/domain this worker is scoped to.",
                            },
                        },
                        "required": ["task"],
                    },
                }
            },
            "required": ["tasks"],
        },
    },
}


# CLI/transport-native — not a platform tool. Lets the model pause the run to
# put a bounded decision to the operator (an exploitation gate, a scope choice)
# with proposed answers, instead of guessing or stopping. Only advertised when
# a caller injects an `ask_handler` (the GUI/CLI foreground loop); a headless
# sub-agent or an unattended run never sees it, so it can't block on a human
# who isn't there.
_ASK_TOOL_NAME = "ask_operator"
_ASK_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": _ASK_TOOL_NAME,
        "description": (
            "Pause and ask the human operator a single, consequential decision "
            "that changes what you do next — e.g. whether to cross from findings "
            "into active exploitation, whether to pull in a newly-discovered "
            "root/sister domain as in-scope, or which of two materially different "
            "paths to take. The run blocks until they answer, then you continue "
            "with their decision. Do NOT use this for trivia, for progress "
            "updates, or to ask permission for an ordinary next tool call — only "
            "for a real fork that needs a human's call. Offer 2-4 concrete "
            "options."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "The decision to put to the operator, in one or two sentences.",
                },
                "options": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 4,
                    "items": {
                        "type": "object",
                        "properties": {
                            "value": {"type": "string", "description": "Short machine value, e.g. 'proceed'."},
                            "label": {"type": "string", "description": "Button text the operator sees."},
                            "detail": {"type": "string", "description": "Optional one-line consequence of this choice."},
                            "intent": {
                                "type": "string",
                                "enum": ["default", "primary", "danger"],
                                "description": "Visual weight; use 'danger' for an exploitation/destructive go.",
                            },
                        },
                        "required": ["value", "label"],
                    },
                },
                "kind": {
                    "type": "string",
                    "enum": ["gate", "scope", "choice"],
                    "description": "'gate' for an exploitation/destructive gate, 'scope' for a scope-expansion decision, else 'choice'.",
                },
                "allow_freeform": {
                    "type": "boolean",
                    "description": "Allow the operator to type a custom answer in addition to the options.",
                },
            },
            "required": ["question", "options"],
        },
    },
}


@dataclass
class Event:
    type: str
    data: dict[str, Any] = field(default_factory=dict)


def _normalize_options(raw: list[Any]) -> list[dict[str, Any]]:
    """Coerce model-supplied options into {value,label,detail?,intent?}, keeping
    only well-formed ones, capped at 4."""
    out: list[dict[str, Any]] = []
    for item in raw[:4]:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or item.get("label") or "").strip()
        label = str(item.get("label") or item.get("value") or "").strip()
        if not value or not label:
            continue
        opt: dict[str, Any] = {"value": value, "label": label}
        detail = str(item.get("detail") or "").strip()
        if detail:
            opt["detail"] = detail
        intent = str(item.get("intent") or "").strip()
        if intent in ("default", "primary", "danger"):
            opt["intent"] = intent
        out.append(opt)
    return out

def _tag_worker_event(worker_num: int, event: Event) -> Event:
    """Copy a spawned worker's event with its origin marked, so the render
    layer (and the operator) can tell "Worker 2 is running nmap" apart from
    the parent loop's own tool calls without changing what either renderer
    already keys off of (tool_name / content)."""
    data = dict(event.data)
    data["source"] = f"worker-{worker_num}"
    if data.get("tool_call_id"):
        data["tool_call_id"] = f"worker-{worker_num}:{data['tool_call_id']}"
    if "tool_name" in data:
        data["tool_name"] = f"[Worker {worker_num}] {data['tool_name']}"
    if "content" in data:
        data["content"] = f"[Worker {worker_num}] {data['content']}"
    if "message" in data:
        data["message"] = f"[Worker {worker_num}] {data['message']}"
    return Event(event.type, data)
