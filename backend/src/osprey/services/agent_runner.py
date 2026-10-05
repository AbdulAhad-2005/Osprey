"""Scoped sub-agent runner — the executable body of a ``kind=agent`` job.

A sub-agent is a headless instance of Osprey's ONE reasoning loop
(``cli.agent.loop.Runner``) — the exact same ReAct loop the interactive CLI
and every CLI-spawned worker use, given no terminal to render into. There is
no second, backend-native agent loop any more (the former ``PhaseAgent`` in
``services/phase_agent.py`` was deleted): two independently-coded loops meant
every fix (context compaction, tool-call error recovery, loop-stall guards,
system-prompt assembly) had to be ported twice by hand, and the backend copy
was thinner (no compaction, no stall/failure guards, its own bespoke system
prompt instead of the CLI's AGENTS.md-driven one) simply because nobody kept
it in sync. Importing the CLI's loop from the backend is an intentionally
unusual dependency direction for a backend service — it is accepted here
because the alternative (two loop implementations) is the actual bug class
this module exists to close; a follow-up may extract ``cli/agent/`` into a
transport-agnostic top-level package so neither side "owns" it, but that is
a naming/packaging cleanup, not a behavior change, and isn't required for
correctness.

It is bound to the SAME engagement, so every finding it records lands in the
shared per-engagement stores (findings/graph/coverage). Its parent — the
phase supervisor, another agent that called ``spawn_agent``, or a harness
driving over MCP — observes those findings through ``platform_findings`` /
``platform_context`` with no bespoke message bus. That shared blackboard IS
the inter-agent communication channel.

Tool calls run through the CLI's embedded platform-mcp gateway
(``cli.agent.tools.EmbeddedToolGateway``), the identical tool surface an
external MCP harness (OpenCode, Claude Code) already drives Osprey through —
so a backend-spawned scoped agent, the interactive CLI, and an external
harness all see the same tool names, the same schemas, and the same
one execution kernel (``tool_execution.execute_tool_request``).
"""

from __future__ import annotations

import logging
import os
import time

from osprey.core.config import get_settings
from osprey.services.agent_common import AgentEventHandler, AgentResponse, AgentToolCall
from osprey.services.engagement_store import get_engagement_store

logger = logging.getLogger(__name__)

# Role → one-line framing injected into the shared system prompt (see
# cli.agent.context.build_system_prompt's ``agent_prompt`` overlay). Roles
# exist so callers name intent ("exploit") rather than internal machinery;
# "custom" is a free-form task with no extra framing beyond the task text.
_ROLE_FRAMING: dict[str, str] = {
    "recon": "You are a scoped background sub-agent focused on the RECON phase: "
    "subdomains, live hosts, ports/services, tech identification. Widen breadth "
    "before depth.",
    "network": "You are a scoped background sub-agent focused on NETWORK/port/service "
    "discovery and version identification (nmap -sV -sC on anything interesting).",
    "vuln": "You are a scoped background sub-agent focused on VULNERABILITY assessment "
    "against surface already discovered elsewhere in this engagement.",
    "web": "You are a scoped background sub-agent focused on web application depth: "
    "paths, params, crawl history, endpoints, JS recon.",
    "exploit": "You are a scoped background sub-agent focused on turning a chainable "
    "vuln/credential/secret into a validated result. RoE gates still apply — "
    "exploitation stays blocked unless the engagement allows it.",
    "osint": "You are a scoped background sub-agent focused on passive intel and "
    "credential/identity leak discovery.",
    "custom": "",
}


def _api_base_url() -> str:
    """This backend's own reachable address — the CLI's embedded gateway
    calls tools over real HTTP even when imported in-process (see
    cli/agent/tools.py), so a backend-spawned agent loops back to itself over
    the network the same way any other client reaches it. Same env var and
    default the CLI itself uses (cli/main.py), so one already-correct setting
    covers both."""
    return os.getenv("API_BASE_URL", "http://localhost:9000")


def _build_task_prompt(role: str, task: str, scope: str) -> str:
    parts: list[str] = []
    if scope.strip():
        parts.append(f"Focus scope: {scope.strip()}.")
    if task.strip():
        parts.append(task.strip())
    else:
        parts.append(
            f"Run the {role} phase against the engagement target — work it deeply "
            "and recursively, and report concrete findings."
        )
    parts.append(
        "Record every concrete finding: sibling agents build on your discoveries "
        "through shared engagement memory, so what you record is what they see."
    )
    return " ".join(parts)


def _resolve_model_config() -> "CLIModelConfig | None":  # noqa: F821 - see import below
    """Build a CLIModelConfig from the backend's OWN settings, not
    ``CLIModelConfig.from_env()``. The two read the same env var names
    (LLM_MODEL/LLM_API_KEY/LLM_API_BASE), but ``get_settings().llm`` prefers
    the live .env FILE over the frozen process env (core/config.py's
    ``settings_customise_sources``) precisely because this backend is a
    long-running process — a plain ``os.getenv()`` read here would silently
    keep serving whatever was baked in at container start, even after an
    operator edits the project .env. Reusing the backend's own resolution
    keeps both drivers reading one live LLM identity from one place."""
    from cli.agent.llm import CLIModelConfig

    settings = get_settings().llm
    model = (settings.model or "").strip()
    api_key = (settings.api_key or "").strip()
    if not model or model == "<model-provider>/<model-name>" or not api_key:
        return None
    return CLIModelConfig(model=model, api_key=api_key, api_base=(settings.api_base or "").strip())


async def run_scoped_agent(
    *,
    engagement_id: str,
    run_id: str = "",
    role: str = "recon",
    task: str = "",
    scope: str = "",
    max_turns: int = 0,
    on_event: AgentEventHandler | None = None,
) -> AgentResponse:
    """Run one scoped, headless CLI-loop worker and return its AgentResponse."""
    from cli.agent.context import build_system_prompt
    from cli.agent.loop import Runner
    from cli.agent.tools import EmbeddedToolGateway
    from osprey.schemas.jobs import AGENT_ROLES

    role = (role or "recon").strip().lower()
    if role not in AGENT_ROLES:
        role = "custom"

    async def emit(event: str, data: dict) -> None:
        if on_event is not None:
            result = on_event(event, data)
            if result is not None:
                await result

    config = _resolve_model_config()
    if config is None:
        message = (
            "No driving model configured for this engagement's backend — set "
            "LLM_MODEL and LLM_API_KEY in the project .env (any LiteLLM-supported "
            "provider) before spawning a scoped agent."
        )
        await emit("error", {"message": message, "phase": role})
        return AgentResponse(success=False, final_message=message, run_id=run_id, phase=role, error="llm_not_configured")

    engagement = get_engagement_store().get(engagement_id) if engagement_id else None
    target = engagement.target if engagement else ""

    gateway = EmbeddedToolGateway(_api_base_url())
    if engagement_id:
        gateway.bind(engagement_id=engagement_id, target=target)

    def worker_factory(*, config, engagement_id, target, tool_filter, agent_prompt):
        # Depth capped at 1 — a spawned worker gets allow_spawn=False, exactly
        # like cli/harness/workers.py's WorkerManager (the interactive CLI's
        # own worker cap) — same rule, same reason, not reinvented here.
        return Runner(
            config=config,
            api_base_url=_api_base_url(),
            engagement_id=engagement_id,
            target=target,
            allow_spawn=False,
            tool_filter=tool_filter,
            agent_prompt=agent_prompt,
            tool_gateway=gateway,
            worker_factory=worker_factory,
        )

    role_framing = _ROLE_FRAMING.get(role, "")
    runner = Runner(
        config=config,
        api_base_url=_api_base_url(),
        engagement_id=engagement_id,
        target=target,
        agent_prompt=role_framing,
        tool_gateway=gateway,
        worker_factory=worker_factory,
        max_turns=max_turns or None,
    )

    system_prompt = await build_system_prompt(
        engagement_id,
        agent_prompt=role_framing,
        tool_caller=gateway.call,
    )
    prompt = _build_task_prompt(role, task, scope)

    # Skills ranked against THIS agent's own task+scope, on top of the base
    # prompt's engagement-wide skill ranking — mirrors Runner._worker_system_prompt
    # (cli/agent/loop.py), the same treatment the interactive CLI already gives
    # every spawned worker, so a role like "exploit" isn't left with only
    # whatever ranked highest for the engagement as a whole.
    query = f"{role_framing} {task} {scope}".strip()
    try:
        skills_text = await gateway.call("platform_skills", {"query": query, "limit": 5} if query else {})
    except Exception:  # noqa: BLE001 - a skills-lookup failure must never block the agent
        skills_text = ""
    if skills_text:
        system_prompt += (
            "\n---\n## SKILLS RANKED FOR YOUR SPECIFIC TASK\n"
            "(pull full text via platform_skills(path=...) if one looks useful)\n" + skills_text
        )

    logger.info(
        "sub-agent start engagement=%s role=%s scope=%r", engagement_id, role, scope,
    )

    tool_calls_log: list[AgentToolCall] = []
    final_message = ""
    success = True
    error: str | None = None
    llm_call_count = 0
    start_time = time.time()

    await emit(
        "phase_start",
        {"phase": role, "agent_role": role, "target": target, "run_id": run_id, "model": config.model},
    )

    try:
        async for event in runner.run(prompt, system_prompt=system_prompt):
            if event.type == "llm_call_start":
                llm_call_count += 1
            elif event.type == "tool_start":
                name = event.data.get("tool_name", "?")
                call_id = event.data.get("tool_call_id", "")
                await emit(
                    "tool_start",
                    {"tool_name": name, "phase": role, "tool_call_id": call_id, "engagement_id": engagement_id},
                )
            elif event.type == "tool_end":
                name = event.data.get("tool_name", "?")
                result_text = str(event.data.get("result", ""))
                ok = bool(event.data.get("success", True))
                duration = float(event.data.get("duration_seconds", 0.0))
                tool_calls_log.append(
                    AgentToolCall(
                        tool_name=name, arguments={}, result=result_text[:500],
                        success=ok, duration_seconds=duration,
                    )
                )
                await emit(
                    "tool_end",
                    {
                        "tool_name": name,
                        "success": ok,
                        "preview": result_text[:500],
                        "duration_seconds": round(duration, 2),
                        "phase": role,
                        "tool_call_id": event.data.get("tool_call_id", ""),
                        "engagement_id": engagement_id,
                    },
                )
            elif event.type in ("thinking", "assistant_text"):
                content = str(event.data.get("content") or "")
                if content:
                    await emit("assistant", {"content": content, "phase": role})
            elif event.type == "error":
                success = False
                error = str(event.data.get("message") or "")
                await emit("error", {"message": error, "phase": role})
            elif event.type == "done":
                final_message = str(event.data.get("content") or "")
    except Exception as exc:  # noqa: BLE001 - never let a scoped agent crash the job worker
        logger.exception("scoped agent error engagement=%s role=%s", engagement_id, role)
        success = False
        error = str(exc)
        final_message = f"Scoped agent error: {exc}"
        await emit("error", {"message": error, "phase": role})

    await emit("phase_done", {"phase": role, "success": success, "tool_calls": len(tool_calls_log)})

    response = AgentResponse(
        success=success,
        final_message=final_message,
        tool_calls=tool_calls_log,
        total_duration_seconds=time.time() - start_time,
        total_llm_calls=llm_call_count,
        total_tool_calls=len(tool_calls_log),
        run_id=run_id,
        phase=role,
        error=error,
    )
    from osprey.services.agent_common import response_event_payload

    await emit("done", {**response_event_payload(response), "model": config.model, "engagement_id": engagement_id})
    return response
