"""Phase-scoped agent — recon or network tools only."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

from osprey.core.config import get_settings
from osprey.platform.situational_context import build_situational_brief
from osprey.schemas.agent_run import PhaseBrief, PhaseHandoff, ToolSummary
from osprey.schemas.engagement import Engagement
from osprey.schemas.jobs import AGENT_ROLES
from osprey.services.agent_arg_normalizer import normalize_agent_tool_args
from osprey.services.agent_assist import AssistState
from osprey.services.agent_common import (
    TOOL_RESULT_MAX,
    AgentEventHandler,
    AgentResponse,
    AgentToolCall,
    build_engagement_context,
    execute_agent_tool,
    extract_inline_tool_call,
    extract_target,
    extract_target_from_history,
    is_recoverable_llm_tool_error,
    llm_tool_error_recovery_message,
    prune_message_history,
    response_event_payload,
    tool_event_display_preview,
    tool_event_quiet,
    tool_result_preview,
    trim_history,
)
from osprey.services.findings_store import get_findings_store
from osprey.services.llm_service import (
    LLMService,
    LLMServiceError,
    get_llm_service,
)
from osprey.services.skills_loader import (
    active_phase_skill_digest,
    load_skills_for_agent,
)
from osprey.services.summary_agent import (
    COMPRESS_THRESHOLD,
    compress_tool_output,
    format_tool_summary_for_context,
    summarize_phase,
)
from osprey.services.target_utils import resolve_ipv4
from osprey.services.tool_discovery import (
    format_tool_result,
    get_tools_for_llm_phase,
)
from osprey.services.tool_registry import list_tools

logger = logging.getLogger(__name__)

_UNAVAILABLE = frozenset({"rustscan_fast_scan"})

# Phases a PhaseAgent / spawned sub-agent may run. Every phase gets the same
# full tool catalog (get_tools_for_llm_phase doesn't filter by phase — an
# agent that stumbles onto something outside its lane can still act on it);
# what actually differs per phase is which skills/<phase>/ digest gets loaded
# into the system prompt. Derived from AGENT_ROLES (the single source of
# truth for "what phases exist") plus "commander" — the root agent isn't a
# spawnable *role* (it's the one PhaseAgent every engagement always has), but
# it is a valid *phase* for this same run() method. Two independently
# hardcoded copies of this set already drifted out of sync once (found via
# the active-directory spawn test) — don't reintroduce a second copy.
_AGENT_PHASES = frozenset(AGENT_ROLES) | {"commander"}


def _max_parallel_tool_calls() -> int:
    """Concurrency cap for tool calls issued in one LLM turn (reuses the job slot cap)."""
    from osprey.services.parallelism_config import max_running_jobs

    return max_running_jobs()


# Control tool every phase agent gets: fan out an independent sub-agent for a
# parallelizable slice of work (a sister domain, one host, one candidate). The
# sub-agent shares this engagement's blackboard, so its findings come back
# through platform_findings — no return channel needed. Bounded by the agent
# concurrency + spawn-budget caps in parallelism_config.
_SPAWN_AGENT_TOOL_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "spawn_agent",
        "description": (
            "Spawn a parallel sub-agent for an independent slice of work (e.g. one "
            "sister domain, one host, one exploit candidate) so you can keep working. "
            "It shares this engagement's findings — its results appear automatically "
            "in your own SESSION FINDINGS on your next turn, no separate lookup needed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "role": {
                    "type": "string",
                    "description": "recon | network | vuln | web | exploit | osint | custom",
                },
                "task": {"type": "string", "description": "What this sub-agent should do"},
                "scope": {"type": "string", "description": "Asset/host/domain to focus on"},
            },
            "required": ["task"],
        },
    },
}

# Control tool: pull the full text of one phase skill on demand. The active
# phase's skill descriptions are already in the prompt; this fetches the one the
# agent judged relevant — the same pull model the MCP path uses, so no executor
# ever truncates a whole skill directory into the prompt.
_READ_SKILL_TOOL_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "read_skill",
        "description": (
            "Read the full text of one phase skill by name (e.g. 'nuclei-scanning'). "
            "The prompt lists each skill's name + description; call this only when a "
            "specific skill is relevant to your next step."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Skill name from the phase index"},
            },
            "required": ["name"],
        },
    },
}

_PLATFORM_SCRIPT_TOOL_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "platform_script",
        "description": (
            "Write and run a short custom python3/bash script in the active engagement. "
            "Use when no typed tool covers the check. Print FINDING|..., PATH ..., or "
            "ENDPOINT ... lines for durable results."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "script_content": {"type": "string", "description": "Full script body"},
                "language": {"type": "string", "description": "python3 | bash | sh"},
                "reason": {"type": "string", "description": "Why this script is needed"},
                "filename": {"type": "string", "description": "Optional relative filename"},
                "packages": {
                    "type": "string",
                    "description": "Comma-separated pip packages for python scripts",
                },
                "timeout": {"type": "integer", "description": "Execution timeout in seconds"},
            },
            "required": ["script_content"],
        },
    },
}

_PLATFORM_SHELL_TOOL_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "platform_shell",
        "description": (
            "Run a focused bash command in the active engagement when no typed tool "
            "fits. Prefer typed tools for catalog scanners and platform_script for "
            "multi-line logic."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Bash command to run"},
                "reason": {"type": "string", "description": "Why this shell command is needed"},
                "timeout": {"type": "integer", "description": "Execution timeout in seconds"},
            },
            "required": ["command"],
        },
    },
}

# Commander-only control tool: the ONE standardized way a full engagement runs.
# Deliberately synchronous — see commander_pipeline.py's module docstring for
# why a background/detached version was tried and replaced.
_COMMANDER_CONTROL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_pipeline",
            "description": (
                "Run the full standardized conductor pipeline (recon -> vuln -> exploit, "
                "evidence-triggered, with loop-back) for the bound target, IN THIS TURN. "
                "This call blocks and streams every step live until the engagement reaches "
                "fixpoint or is interrupted — it is the ONE way to run a full pentest, "
                "identical to how an external harness runs its own subagents through the "
                "same conductor. Do not call other typed tools in the same turn as this "
                "one; wait for it to return, then continue based on its result."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
    },
]

_COMMANDER_SYSTEM = """You are the Commander of an autonomous pentest platform — an elite operator, \
not a phase machine. A user talks to you in free form, exactly like a coding agent.

WHAT YOU OWN:
- The full tool catalog (any registered tool) for narrow, targeted work.
- run_pipeline: the ONE standardized way to run a complete engagement.

HOW YOU DECIDE each message:
- Just answer  -> reply in plain text (a question, a plan, a summary).
- One probe    -> call a single tool and interpret the result.
- Full pentest -> call run_pipeline and let it run. It IS the standardized
  recon->vuln->exploit sequence — the same one an external harness runs via its
  own subagents through this same conductor. Watch it work, live, in this turn.
  Do NOT also call typed recon/vuln/network tools yourself while it runs — that
  duplicates its work. The user can interrupt at any time if it should stop.
- Targeted parallel work -> spawn_agent for one explicit, narrow slice the user
  asked for (a sister domain, one host) — never as your own invented substitute
  for a full pentest.

RULES:
- The engagement/target is already bound for you when the user named one — never
  demand a set_target ceremony. If no target is bound and the user hasn't named one,
  ask once for a domain/IP/CIDR/URL.
- Ground truth is the engagement graph + findings, not chat memory. Skills sharpen
  judgment; evidence decides the next step.
- Be honest about what is proven vs hypothesised. Stop and summarise when the goal is met."""

_PHASE_SYSTEM = """You are a phase specialist in an autonomous pentest platform — not a script runner.

HOW YOU THINK:
- Read CURRENT SITUATION before every tool call.
- Pick ONE purposeful next step that closes a specific gap.
- Skills and tool lists are background knowledge — evidence decides what happens next.
- Use additional_args for any valid CLI flags not covered by typed params.
- After every tool run: read output and FAILURE ANALYSIS; adapt or stop when the goal is met.

CRITICAL RULES:
- If a tool reports "command not found", do NOT retry it this session.
- If permission denied, pick an unprivileged alternative.
- Do not duplicate domain/target flags in additional_args.
- Run only tools available in your phase catalog.

When the phase goal is met, stop and summarize in plain language."""


@dataclass
class PhaseAgentResult:
    agent: AgentResponse
    brief: PhaseBrief


class PhaseAgent:
    """ReAct loop scoped to recon or network phase tools."""

    def __init__(self, llm: LLMService | None = None) -> None:
        self._llm = llm or get_llm_service()

    async def run(
        self,
        prompt: str,
        engagement: Engagement | None = None,
        *,
        phase: str,
        run_id: str | None = None,
        conversation_history: list[dict[str, Any]] | None = None,
        max_turns: int | None = None,
        handoff: PhaseHandoff | None = None,
        commander_note: str = "",
        on_event: AgentEventHandler | None = None,
    ) -> PhaseAgentResult:
        if phase not in _AGENT_PHASES:
            response = AgentResponse(
                success=False,
                final_message=f"PhaseAgent supports {sorted(_AGENT_PHASES)}, got '{phase}'.",
                phase=phase,
                error="invalid_phase",
            )
            return PhaseAgentResult(agent=response, brief=PhaseBrief(phase=phase))

        start_time = time.time()
        turns = max_turns or get_settings().llm.max_agent_turns
        session_run_id = run_id or uuid.uuid4().hex[:12]
        engagement_id = engagement.id if engagement else ""
        tool_calls_log: list[AgentToolCall] = []
        tool_summaries: list[ToolSummary] = []
        llm_call_count = 0
        assist_state = AssistState()

        session_target = (
            (engagement.target if engagement else None)
            or (handoff.target if handoff else None)
            or extract_target(prompt)
            or extract_target_from_history(conversation_history)
        )
        resolved_ip = (
            (handoff.resolved_ip if handoff else None)
            or (resolve_ipv4(session_target) if session_target else None)
        )
        provide_tools = session_target is not None

        if provide_tools:
            installed_names = {t.name for t in list_tools() if t.installed}
            tools_schema = [
                t
                for t in get_tools_for_llm_phase(phase, compact=True)
                if t.get("function", {}).get("name") in installed_names
                and t.get("function", {}).get("name") not in _UNAVAILABLE
            ]
            # Every phase agent can fan out parallel sub-agents and pull skills.
            tools_schema.append(_SPAWN_AGENT_TOOL_SCHEMA)
            tools_schema.append(_READ_SKILL_TOOL_SCHEMA)
            tools_schema.append(_PLATFORM_SCRIPT_TOOL_SCHEMA)
            tools_schema.append(_PLATFORM_SHELL_TOOL_SCHEMA)
            # The Commander additionally owns the conductor as a background job.
            if phase == "commander":
                tools_schema.extend(_COMMANDER_CONTROL_SCHEMAS)
        else:
            tools_schema = []

        def system_prompt(*, turn: int = 0) -> str:
            return _build_phase_system_prompt(
                phase=phase,
                engagement_id=engagement_id,
                run_id=session_run_id,
                session_target=session_target,
                resolved_ip=resolved_ip,
                assist_state=assist_state,
                user_goal=prompt,
                commander_note=commander_note,
                turn=turn,
                max_turns=turns,
            )

        system_content = system_prompt()
        if not provide_tools:
            system_content += (
                "\n\nNO TARGET YET: Reply in plain text and ask for the domain or IP. Do not call tools."
            )

        messages: list[dict[str, Any]] = [{"role": "system", "content": system_content}]

        if engagement:
            messages.append({"role": "user", "content": build_engagement_context(engagement)})
            messages.append(
                {"role": "assistant", "content": "Understood. I'll work within the engagement scope and rules."}
            )

        if handoff:
            messages.append({"role": "user", "content": handoff.to_prompt()})
            messages.append(
                {"role": "assistant", "content": "Handoff received. I'll use prior findings as ground truth."}
            )

        if conversation_history:
            messages.extend(trim_history(conversation_history))

        user_content = prompt
        if commander_note:
            user_content = f"{prompt}\n\nCOMMANDER NOTE:\n{commander_note}"
        messages.append({"role": "user", "content": user_content})

        async def emit(event: str, data: dict[str, Any]) -> None:
            if on_event:
                result = on_event(event, data)
                if result is not None:
                    await result

        await emit(
            "phase_start",
            {
                "phase": phase,
                "agent_role": phase,
                "target": session_target,
                "tools": len(tools_schema),
                "run_id": session_run_id,
                "model": self._llm.model,
            },
        )

        llm_schema_retries = 0

        for turn in range(turns):
            try:
                messages[0]["content"] = system_prompt(turn=turn)

                await emit("status", {"message": f"[{phase}] Thinking (turn {turn + 1})...", "turn": turn + 1, "phase": phase})

                try:
                    response = await self._llm.complete(
                        messages=messages,
                        tools=tools_schema if tools_schema else None,
                    )
                except LLMServiceError as exc:
                    err = str(exc)
                    if is_recoverable_llm_tool_error(err) and llm_schema_retries < 2:
                        llm_schema_retries += 1
                        messages.append({"role": "user", "content": llm_tool_error_recovery_message(err)})
                        continue
                    raise

                llm_schema_retries = 0
                llm_call_count += 1

                message = response["choices"][0]["message"]
                messages.append(message)

                tool_calls = message.get("tool_calls")
                if not tool_calls:
                    inline = extract_inline_tool_call(message.get("content", "") or "")
                    if inline:
                        tool_calls = [inline]

                if not tool_calls:
                    final = message.get("content", "") or ""
                    await emit("assistant", {"content": final, "phase": phase})
                    agent_response = self._make_response(
                        True, final, tool_calls_log, start_time, llm_call_count, session_run_id, phase
                    )
                    brief = await self._brief(phase, session_target, resolved_ip, tool_summaries, engagement_id, session_run_id)
                    await emit("phase_done", {"phase": phase, "success": True, "tool_calls": len(tool_calls_log)})
                    await emit("done", {**response_event_payload(agent_response), "model": self._llm.model, "engagement_id": engagement_id})
                    return PhaseAgentResult(agent=agent_response, brief=brief)

                # A single LLM turn often emits several independent tool calls
                # (e.g. httpx + naabu + whatweb on the same host). Run them
                # concurrently under the global job-slot cap instead of serially
                # — the tools are I/O-bound, so this is a large latency win — but
                # append the tool-result messages back in the model's original
                # call order so the conversation stays deterministic.
                async def _handle_tool_call(tc: dict[str, Any]) -> dict[str, Any]:
                    fn = tc["function"]
                    # Models sometimes emit an MCP-style server namespace prefix
                    # (e.g. "cyber_recon:platform_health") they hallucinated from
                    # the shared skills — strip it so the bare tool name resolves.
                    tool_name = str(fn["name"]).split(":")[-1].strip()
                    try:
                        tool_args = json.loads(fn.get("arguments", "{}"))
                    except json.JSONDecodeError:
                        tool_args = {}
                    tool_args, norm_notes = normalize_agent_tool_args(tool_name, tool_args)

                    await emit(
                        "tool_start",
                        {
                            "tool_name": tool_name,
                            "arguments": tool_args,
                            "phase": phase,
                            "tool_call_id": tc["id"],
                            "engagement_id": engagement_id,
                            "display_quiet": tool_event_quiet(tool_name),
                        },
                    )
                    exec_start = time.time()
                    result_text, success, tool_response = await execute_agent_tool(
                        tool_name=tool_name,
                        tool_args=tool_args,
                        engagement_id=engagement_id or None,
                        run_id=session_run_id,
                        assist_state=assist_state,
                        target=session_target or "",
                        phase=phase,
                        user_goal=prompt,
                        norm_notes=norm_notes,
                        on_event=emit,
                    )
                    exec_duration = time.time() - exec_start

                    summary = None
                    if tool_response and len(tool_response.stdout or "") >= COMPRESS_THRESHOLD:
                        summary = await compress_tool_output(
                            tool_response,
                            finding_titles=tool_response.finding_titles,
                        )
                        await emit(
                            "summary",
                            {
                                "phase": phase,
                                "tool_name": tool_name,
                                "raw_chars": len(tool_response.stdout or ""),
                                "key_facts": len(summary.key_facts),
                            },
                        )
                        result_text = f"{result_text}\n\n---\n{format_tool_summary_for_context(summary)}"

                    result_text = format_tool_result(tool_name, result_text, max_length=TOOL_RESULT_MAX)
                    event_payload = {
                        "tool_name": tool_name,
                        "success": success,
                        "duration_seconds": round(exec_duration, 2),
                        "preview": tool_result_preview(result_text, success),
                        "display_preview": tool_event_display_preview(
                            tool_name=tool_name,
                            result_text=result_text,
                            success=success,
                            tool_response=tool_response,
                        ),
                        "display_quiet": tool_event_quiet(tool_name, success=success),
                        "phase": phase,
                        "tool_call_id": tc["id"],
                        "engagement_id": engagement_id,
                    }
                    if tool_response is not None:
                        artifacts = {}
                        if isinstance(tool_response.hybrid, dict):
                            artifacts = tool_response.hybrid.get("artifacts") or {}
                        event_payload.update(
                            {
                                "command": tool_response.command,
                                "returncode": tool_response.returncode,
                                "stdout_path": artifacts.get("stdout_path", ""),
                                "stderr_path": artifacts.get("stderr_path", ""),
                                "finding_titles": tool_response.finding_titles,
                                "cache_hit": tool_response.cache_hit,
                                "next_hint": tool_response.next_hint,
                                "artifacts": artifacts,
                            }
                        )
                    else:
                        event_payload["stdout"] = result_text
                    await emit("tool_end", event_payload)
                    return {
                        "tool_call_id": tc["id"],
                        "tool_name": tool_name,
                        "tool_args": tool_args,
                        "result_text": result_text,
                        "success": success,
                        "duration": exec_duration,
                        "summary": summary,
                    }

                # run_pipeline must never run alongside other tool calls in the same
                # batched turn — that would let the model freelance other typed
                # tools "at the same time" as the one call meant to cover the whole
                # engagement, silently reproducing the exact duplicated-work problem
                # this design exists to eliminate. Every originally-requested
                # tool_call_id still gets a response (API contract); the extras just
                # get told why they were skipped instead of running.
                skipped_calls: list[dict[str, Any]] = []
                if len(tool_calls) > 1:
                    pipeline_call = next(
                        (tc for tc in tool_calls if tc["function"]["name"].split(":")[-1].strip() == "run_pipeline"),
                        None,
                    )
                    if pipeline_call is not None:
                        skipped_calls = [tc for tc in tool_calls if tc is not pipeline_call]
                        tool_calls = [pipeline_call]

                if len(tool_calls) == 1:
                    results = [await _handle_tool_call(tool_calls[0])]
                else:
                    turn_sem = asyncio.Semaphore(max(1, _max_parallel_tool_calls()))

                    async def _bounded(tc: dict[str, Any], sem: asyncio.Semaphore = turn_sem) -> dict[str, Any]:
                        async with sem:
                            return await _handle_tool_call(tc)

                    results = await asyncio.gather(*(_bounded(tc) for tc in tool_calls))

                for tc in skipped_calls:
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": (
                            "SKIPPED: run_pipeline was called in the same turn — it already "
                            "covers the full engagement. Wait for it to return, then continue."
                        ),
                    })

                for res in results:
                    if res["summary"] is not None:
                        tool_summaries.append(res["summary"])
                    tool_calls_log.append(
                        AgentToolCall(
                            tool_name=res["tool_name"],
                            arguments=res["tool_args"],
                            result=res["result_text"][:500],
                            success=res["success"],
                            duration_seconds=res["duration"],
                        )
                    )
                    messages.append(
                        {"role": "tool", "tool_call_id": res["tool_call_id"], "content": res["result_text"]}
                    )

                prune_message_history(messages)

            except Exception as e:
                logger.exception("PhaseAgent error on turn %d", turn)
                await emit("error", {"message": str(e), "phase": phase})
                agent_response = self._make_response(
                    False, f"Phase agent error: {e}", tool_calls_log, start_time, llm_call_count, session_run_id, phase, error=str(e)
                )
                brief = await self._brief(phase, session_target, resolved_ip, tool_summaries, engagement_id, session_run_id)
                await emit("phase_done", {"phase": phase, "success": False})
                await emit("done", {**response_event_payload(agent_response), "model": self._llm.model, "engagement_id": engagement_id})
                return PhaseAgentResult(agent=agent_response, brief=brief)

        agent_response = self._make_response(
            False,
            f"Reached maximum turns ({turns}) in {phase}. "
            f"Executed {len(tool_calls_log)} tools — send another message to continue.",
            tool_calls_log,
            start_time,
            llm_call_count,
            session_run_id,
            phase,
            error="max_turns_exceeded",
        )
        brief = await self._brief(phase, session_target, resolved_ip, tool_summaries, engagement_id, session_run_id)
        await emit("phase_done", {"phase": phase, "success": False, "reason": "max_turns"})
        await emit("done", {**response_event_payload(agent_response), "model": self._llm.model, "engagement_id": engagement_id})
        return PhaseAgentResult(agent=agent_response, brief=brief)

    def _make_response(
        self,
        success: bool,
        final_message: str,
        tool_calls_log: list[AgentToolCall],
        start_time: float,
        llm_call_count: int,
        run_id: str,
        phase: str,
        *,
        error: str | None = None,
    ) -> AgentResponse:
        return AgentResponse(
            success=success,
            final_message=final_message,
            tool_calls=tool_calls_log,
            total_duration_seconds=time.time() - start_time,
            total_llm_calls=llm_call_count,
            total_tool_calls=len(tool_calls_log),
            run_id=run_id,
            phase=phase,
            error=error,
        )

    async def _brief(
        self,
        phase: str,
        target: str | None,
        resolved_ip: str | None,
        tool_summaries: list[ToolSummary],
        engagement_id: str,
        run_id: str,
    ) -> PhaseBrief:
        return await summarize_phase(
            phase,
            target=target or "",
            resolved_ip=resolved_ip,
            tool_summaries=tool_summaries,
            engagement_id=engagement_id,
            run_id=run_id,
        )


_TURN_URGENCY_BANDS: tuple[tuple[float, str], ...] = (
    (0.95, "95%+ of your turn budget is used. Wrap up now: persist what you have and stop."),
    (0.85, "85%+ of your turn budget is used. Prioritize the highest-value remaining item only."),
    (0.70, "70%+ of your turn budget is used. Start converging — avoid opening new broad threads."),
)


def _turn_urgency_note(turn: int, max_turns: int) -> str:
    if max_turns <= 0:
        return ""
    frac = turn / max_turns
    for threshold, note in _TURN_URGENCY_BANDS:
        if frac >= threshold:
            return f"TURN BUDGET: {turn}/{max_turns} used. {note}"
    return ""


def _build_phase_system_prompt(
    *,
    phase: str,
    engagement_id: str,
    run_id: str,
    session_target: str | None,
    resolved_ip: str | None,
    assist_state: AssistState | None,
    user_goal: str,
    commander_note: str = "",
    turn: int = 0,
    max_turns: int = 0,
) -> str:
    is_commander = phase == "commander"
    base_system = _COMMANDER_SYSTEM if is_commander else _PHASE_SYSTEM
    sections = [base_system]
    if not is_commander:
        sections.append(f"ACTIVE PHASE: {phase}")

    urgency = _turn_urgency_note(turn, max_turns)
    if urgency:
        sections.append(urgency)

    if is_commander:
        skills = load_skills_for_agent("commander")
        if skills:
            sections.append(f"COMMANDER SKILLS:\n{skills}")
    else:
        skills = active_phase_skill_digest(phase)
        if skills:
            sections.append(f"PHASE SKILLS:\n{skills}")

    if session_target:
        sections.append(f"TARGET: {session_target}")
    if resolved_ip:
        sections.append(f"RESOLVED_IP: {resolved_ip}")

    if commander_note:
        sections.append(f"COMMANDER CONSTRAINTS:\n{commander_note}")

    situational = build_situational_brief(
        engagement_id=engagement_id,
        run_id=run_id,
        target=session_target or "",
        resolved_ip=resolved_ip,
        phase=phase,
        assist_state=assist_state,
        user_goal=user_goal,
    )
    if situational:
        sections.append(situational)

    findings = get_findings_store().structured_summary_for_agent(
        engagement_id=engagement_id,
        run_id=run_id,
    )
    if findings and not findings.startswith("No findings"):
        sections.append(f"SESSION FINDINGS:\n{findings[:1400]}")

    return "\n\n---\n\n".join(sections)


_phase_agent: PhaseAgent | None = None


def get_phase_agent() -> PhaseAgent:
    global _phase_agent
    if _phase_agent is None:
        _phase_agent = PhaseAgent()
    return _phase_agent
