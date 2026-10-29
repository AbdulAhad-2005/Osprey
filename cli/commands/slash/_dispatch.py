from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.commands.scan_shared import (
    _api_error_text,
)
from cli.ui.display import (
    print_error,
)
from cli.commands.slash._findings import handle_anomalies, handle_attackpath, handle_context, handle_file, handle_finding, handle_findings, handle_fp, handle_hypothesis, handle_link, handle_observations, handle_priority, handle_question, handle_record, handle_report, handle_skill, handle_skills, handle_world
from cli.commands.slash._meta import handle_agent, handle_chat, handle_clear, handle_config, handle_details, handle_engagements, handle_exit, handle_health, handle_help, handle_model, handle_models, handle_profile, handle_reconnect, handle_reset, handle_status, handle_tool, handle_tools
from cli.commands.slash._scan import handle_cancel, handle_fast_scan, handle_job, handle_jobs, handle_pause, handle_resume, handle_scan



SLASH_COMMANDS: dict[str, tuple[str, "callable"]] = {
    "/help": ("Show help", handle_help),
    "/health": ("Check backend health", handle_health),
    "/tools": ("List MCP tools", handle_tools),
    "/models": ("List LLM models", handle_models),
    "/model": ("Show active model, or `/model reload` to re-read .env in place", handle_model),
    "/scan": ("Bind target + run full agent scan", handle_scan),
    "/fast-scan": ("Deterministic no-LLM scan: whois+subs+SANs+IPs+CDN-classify+httpx+nmap+takeover", handle_fast_scan),
    "/jobs": ("List durable jobs for the active engagement", handle_jobs),
    "/job": ("Show one job's current state and recent log", handle_job),
    "/pause": ("Pause deterministic investigation scheduling", handle_pause),
    "/resume": ("Resume a paused deterministic investigation", handle_resume),
    "/cancel": ("Cancel the active investigation or a named job", handle_cancel),
    "/engage": ("Manage engagements", handle_engagements),
    "/findings": ("Show findings", handle_findings),
    "/finding": ("Act on one finding by id (fp <id> [reason] | reverify <id> | confirm <id> [note])", handle_finding),
    "/fp": ("FP-cache patterns: list | remove <id>", handle_fp),
    "/observations": ("List stored Observations (structural facts, not verdicts)", handle_observations),
    "/file": ("File an evidence-backed finding (no confidence flag — evidence computes it)", handle_file),
    "/world": ("Query the world model: assets|related|incomplete|unexplained|conflicts", handle_world),
    "/priority": ("What's worth doing next: top items, or phase <vuln|exploit> unlock status", handle_priority),
    "/anomalies": ("What looks statistically weird right now (peer timing/version drift)", handle_anomalies),
    "/context": ("Show the context packet — the same world-model state injected into every LLM turn", handle_context),
    "/skills": ("Browse/query the skill library: list | find <query> | get <path>", handle_skills),
    "/link": ("Create an operator-named graph edge between two assets", handle_link),
    "/record": ("Record a reasoned conclusion no tool output backs (confidence is computed, not asserted)", handle_record),
    "/attackpath": ("Attack path chains: propose | advance | list | get", handle_attackpath),
    "/question": ("Open questions: raise | list | answer | dismiss", handle_question),
    "/hypothesis": ("Active hypotheses: raise | list | evidence | resolve", handle_hypothesis),
    "/report": ("Write a Markdown recon report to ./reports/", handle_report),
    "/tool": ("Show or expand tool-call output", handle_tool),
    "/output": ("Alias for /tool", handle_tool),
    "/chat": ("Show this CLI session's conversation", handle_chat),
    "/details": ("Set live tool detail level", handle_details),
    "/status": ("Session status", handle_status),
    "/skill": ("Review/approve LLM-proposed learned skills", handle_skill),
    "/profile": ("Your operator profile — add prefs or approve LLM-inferred ones", handle_profile),
    "/agent": ("Switch prompt-defined flow/mode (.osprey/agents/*.md)", handle_agent),
    "/config": ("Show configuration", handle_config),
    "/reconnect": ("Re-read .env and reconnect to backend", handle_reconnect),
    "/reset": ("Clear agent conversation", handle_reset),
    "/clear": ("Clear screen", handle_clear),
    "/exit": ("Exit the CLI", handle_exit),
    "/quit": ("Exit the CLI", handle_exit),
    "/q": ("Exit the CLI", handle_exit),
}


def execute_command(command_line: str, client: "APIClient") -> bool:
    """Execute a slash command. Returns False if the user wants to exit."""
    parts = command_line.strip().split()
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd in {"/exit", "/quit", "/q"}:
        return False

    if cmd in SLASH_COMMANDS:
        _, handler = SLASH_COMMANDS[cmd]
        try:
            handler(args, client)
        except httpx.RequestError as exc:
            # The REPL deliberately remains usable when the backend is down.
            # A slash command should therefore report transport failure and
            # return to the prompt, never tear down the whole session.
            print_error(_api_error_text(exc))
        return True

    # Prompt-defined custom command? .osprey/commands/<name>.md — expand its
    # template with the args and drive it as a normal prompt. Zero code, no restart.
    from agent_core.flows import expand_command, load_commands

    cmds = load_commands()
    name = cmd.lstrip("/")
    if name in cmds:
        from cli.commands.prompt import handle_prompt

        handle_prompt(expand_command(cmds[name].template, args), client)
        return True

    print_error(f"Unknown command: {cmd}. Type /help for available commands.")
    return True
