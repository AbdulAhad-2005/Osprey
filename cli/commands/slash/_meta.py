from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.commands.scan_shared import (
    _api_error_text,
    _bind_engagement,
)
from cli.ui.display import (
    print_chat_history,
    print_command_help,
    print_engagements,
    print_error,
    print_health,
    print_info,
    print_models,
    print_success,
    print_tool_detail,
    print_tool_history,
    print_tools,
)

def handle_help(args: list[str], client: "APIClient") -> None:
    commands = {
        "/help": "Show this help message",
        "/health": "Check backend service health",
        "/tools [--all]": (
            "Show missing tools + how to install each (default), or every "
            "registered tool with --all"
        ),
        "/models": "List supported LLM models",
        "/model [reload]": "Show active LLM model; `reload` re-reads .env model/key in place (keeps engagement)",
        "/scan [target] [--engine|--supervised] [--fresh]": (
            "Bind target + run a full pentest. Default: the model drives every "
            "tool itself (full LLM judgment/cost). --engine: deterministic, "
            "no-LLM opportunity engine. --supervised: the deterministic engine "
            "runs itself with the LLM checking in only at bounded checkpoints "
            "-- zero tokens on the obvious mechanical work, full LLM judgment "
            "when there's actually something worth deciding. --fresh: start a "
            "brand-new engagement instead of reusing an existing one."
        ),
        "/fast-scan <target> [--engine]": (
            "Narrow, deterministic, no-LLM scan: whois -> subdomain enum (no sister "
            "domains) -> TLS SAN pass -> resolve IPs+CNAMEs -> classify CDN vs origin "
            "-> httpx live-probe -> nmap deep scan (full on origin, light on CDN edges) "
            "-> takeover check. Faster/narrower than /scan --engine."
        ),
        "/engage list": "List all engagements",
        "/engage new <target>": "Create a new engagement",
        "/engage set <id>": "Bind this session to an existing engagement",
        "/findings [keyword] [--all] [--flat]": (
            "Show findings, grouped by issue pattern (noise excluded; --all shows everything; --flat = one row per instance)"
        ),
        "/observations [type] [--target <t>] [--limit N]": "List stored Observations — structural facts, not verdicts",
        '/file <type> <obs_id,...> "<title>" [--severity ..] [--evidence ..]': "File an evidence-backed finding",
        "/finding fp <id> [--scope <glob>] [reason...]": "Mark a finding as noise (scoped to its own target by default)",
        "/fp list | remove <id>": "Audit/prune FP-cache patterns",
        "/world assets|related|incomplete|unexplained|conflicts [asset_id]": "Query the observation-backed graph",
        "/priority [--kinds ..] [--limit N] | phase vuln|exploit": "What's worth doing next (multi-factor, decay-aware)",
        "/anomalies [--engagement <id>]": "Peer-comparison outliers (timing/version drift) — feeds priority's unexplained_behavior",
        "/context": "Show the context packet (world model, priorities, coverage, questions, attack paths, RoE)",
        '/skills find "<query>" [--phase ..] [--mitre ..] [--asset-type ..]': "Ranked skill retrieval (replaces flat browsing at scale)",
        '/link <source> <relation> <target> "<evidence>" [--confidence ..]': "Create an operator-named graph edge",
        '/record <type> "<title>" "<evidence>" [--severity ..] [--desc ..]': "Record a reasoned conclusion (evidence -> attestation; confidence computed)",
        '/attackpath propose "<title>" <kind> <ref_id> ["<why>"]': "Start an attack-path chain",
        "/attackpath advance <id> [--status ..] [--finding ..] [--step ..]": "Add a hop / resolve a chain",
        "/attackpath list [--all] | get <id>": "Review attack-path chains",
        '/question raise "<text>" | list [--all] | answer <id> "..." | dismiss <id>': "Reasoning scaffold: open questions",
        '/hypothesis raise "<statement>" | list [--all] | evidence <id> .. | resolve <id> ..': "Reasoning scaffold: active hypotheses",
        "/report [--engagement <id>]": (
            "Write a Markdown recon report (seed -> sisters -> subdomains -> IPs -> ports/services/tech, WHOIS/OSINT, vulns) to ./reports/"
        ),
        "/tool [id]": "List recent tool calls, or open one full command/output transcript",
        "/output [id]": "Alias for /tool [id]",
        "/chat": "Show this CLI session's conversation",
        "/details [compact|preview|verbose]": "Cycle or set live tool output detail level",
        "/pause": "Pause deterministic investigation scheduling; active job keeps running",
        "/resume": "Reattach to a paused investigation and continue",
        "/cancel [job_id]": "Cancel the active investigation/job while preserving evidence",
        "/status": "Show current session status (auto-refreshes config)",
        "/jobs [status]": "List durable jobs for the active engagement",
        "/job <id>": "Show current state and recent log lines for one job",
        "/cancel <id>": "Cancel a job; evidence gathered so far remains saved",
        "/config": "Show config (auto-refreshes from .env)",
        "/config reload": "Force backend to re-read .env",
        "/reconnect": "Re-read .env and reconnect to changed API_BASE_URL",
        "/reset": "Clear agent conversation memory for this CLI session",
        "/clear": "Clear the terminal screen",
        "/exit | /quit | /q": "Exit the CLI",
    }
    print_command_help(commands)
    print_info("")
    print_info("LLM Setup:")
    print_info("  Set LLM_MODEL and LLM_API_KEY in your .env file to enable the agent.")
    print_info("  Examples:")
    print_info("    LLM_MODEL=deepseek/deepseek-chat  LLM_API_KEY=sk-...")
    print_info("    LLM_MODEL=openai/gpt-4o            LLM_API_KEY=sk-...")
    print_info("    LLM_MODEL=anthropic/claude-sonnet-4-20250514  LLM_API_KEY=sk-ant-...")
    print_info("    LLM_MODEL=groq/llama-3.1-70b       LLM_API_KEY=gsk_...")
    print_info("    LLM_MODEL=ollama/llama3.1           (no key needed)")


def handle_health(args: list[str], client: "APIClient") -> None:
    try:
        data = client.health()
        print_health(data)
    except Exception as exc:
        print_error(str(exc))


def handle_tools(args: list[str], client: "APIClient") -> None:
    show_all = any(a in ("--all", "all") for a in args)
    tools = client.list_tools()
    print_tools(tools, show_all=show_all)


def handle_models(args: list[str], client: "APIClient") -> None:
    models = client.list_models()
    print_models(models)


def handle_model(args: list[str], client: "APIClient") -> None:
    """Show both models in play: the CLI's own driving model (what runs your
    prompts, in this process) and the backend's (what the deterministic
    `--engine` path's dynamic-fallback ingestion classifier uses, if
    configured — a separate, optional concern from what's driving you).

    `/model reload` re-reads .env and rebuilds the driving model in place —
    without dropping the engagement — so you can switch provider/model after a
    rate limit and keep going (unlike /reconnect, which clears the session)."""
    if args and args[0].lower() in ("reload", "refresh"):
        import os

        from dotenv import load_dotenv

        load_dotenv(override=True)  # edited .env wins over the stale process env
        from cli.harness import get_runtime

        get_runtime(client).reload_model()
        model = (os.getenv("LLM_MODEL") or "").strip() or "NOT CONFIGURED"
        print_success(f"Reloaded driving model from .env: {model} (engagement kept).")
        return
    _print_cli_model_status()
    print_info("")
    _reload_backend_config(client)
    try:
        resp = client._client.get(f"{client.base_url}/api/v1/models/active")
        resp.raise_for_status()
        data = resp.json()
        print_info(f"Backend model:       {data.get('model', '?')}")
        print_info(f"Backend API Key:     {'configured' if data.get('has_api_key') else 'NOT SET'}")
        print_info(f"Backend Custom Base: {data.get('has_custom_base', False)}")
        print_info(f"Backend Max Tokens:  {data.get('max_tokens', '?')}")
        print_info(f"Backend Temperature: {data.get('temperature', '?')}")
    except Exception as exc:
        print_error(str(exc))


def _print_cli_model_status() -> None:
    """The model actually driving your prompts — independent of whatever the
    backend's own .env has configured (see agent_core/llm.py)."""
    from agent_core.llm import CLIModelConfig, LLMNotConfiguredError

    try:
        config = CLIModelConfig.from_env()
        print_info(f"CLI driving model:   {config.model}")
        print_info("CLI API Key:         configured")
    except LLMNotConfiguredError:
        print_info("CLI driving model:   NOT CONFIGURED — set LLM_MODEL and LLM_API_KEY in your own .env")


def handle_engagements(args: list[str], client: "APIClient") -> None:
    if not args or args[0] == "list":
        engagements = client.list_engagements()
        print_engagements(engagements)
    elif args[0] == "new" and len(args) >= 2:
        target = " ".join(args[1:])
        try:
            data = client.compile_engagement_for_target(target, force_new=True)
            _bind_engagement(client, data)
        except Exception as exc:
            print_error(_api_error_text(exc))
    elif args[0] == "set" and len(args) >= 2:
        try:
            data = client.get_engagement(args[1])
            _bind_engagement(client, data)
        except Exception as exc:
            print_error(_api_error_text(exc))
    else:
        print_info("Usage: /engage list | /engage new <target> | /engage set <engagement_id>")


def _take_flag(args: list[str], flag: str) -> tuple[str | None, list[str]]:
    """Extract `--flag value` from args, returning (value, remaining_args)."""
    if flag in args:
        idx = args.index(flag)
        if idx + 1 < len(args):
            return args[idx + 1], args[:idx] + args[idx + 2:]
        return None, args[:idx] + args[idx + 1:]
    return None, args


def _require_engagement(engagement_id: str | None) -> bool:
    if engagement_id:
        return True
    print_info("No engagement bound. Run /scan <target> or /engage new <target> first.")
    return False


def _reload_backend_config(client: "APIClient") -> bool:
    """Trigger backend config reload from .env. Returns True on success."""
    try:
        client._client.post(f"{client.base_url}/api/v1/config/reload")
        return True
    except Exception:
        return False


def handle_status(args: list[str], client: "APIClient") -> None:
    from cli.harness import get_runtime

    runtime = get_runtime(client)
    # Auto-reload backend config first so status is always fresh
    _reload_backend_config(client)

    try:
        health = client.health()
        backend_status = "connected" if health.get("status") == "ok" else "degraded"
    except Exception:
        backend_status = "disconnected"

    print_info(f"Backend: {backend_status}")
    print_info(f"API URL:  {client.base_url}")
    print_info(f"Details:  {runtime.transcript.detail_mode}")

    active = client.active_engagement_id
    if active:
        print_info(f"Engagement: {active}")
        activity = client.get_pipeline_activity(active)
        agents_line = activity.get("agents_line")
        readiness = activity.get("phase_readiness_text")
        active_agents = activity.get("active_agents") or []
        if agents_line:
            print_info(f"Pipeline:   {agents_line}")
        if readiness:
            print_info(f"Readiness:  {readiness}")
        if active_agents:
            print_info(f"Agents:     {len(active_agents)} active")
    else:
        print_info("Engagement: none — run /scan <target> or /engage new <target>")

    _print_cli_model_status()

    # Backend model — a separate, optional concern (drives the deterministic
    # --engine path's dynamic-fallback ingestion classifier, if configured).
    try:
        resp = client._client.get(f"{client.base_url}/api/v1/agent/status")
        resp.raise_for_status()
        data = resp.json()
        print_info(f"Backend model: {data.get('model', '?')}")
        print_info(f"Backend OK:    {'yes' if data.get('model_active') else 'no — not configured'}")
        print_info(f"Tools:         {data.get('tools_available', 0)} available")
    except Exception:
        pass
    recent = runtime.transcript.recent(1)
    if recent:
        last = recent[-1]
        print_info(f"Last tool: #{last.id} {last.tool_name} ({last.status_text})")


def handle_config(args: list[str], client: "APIClient") -> None:
    """Show BACKEND config and optionally reload its .env — the deterministic
    --engine path's own settings. Your own driving model is separate; see
    /model or /status."""
    if args and args[0] == "reload":
        try:
            resp = client._client.post(f"{client.base_url}/api/v1/config/reload")
            resp.raise_for_status()
            data = resp.json()
            print_success(f"Config reloaded: model={data['model']}, api_key={'set' if data['has_api_key'] else 'NOT SET'}")
        except Exception as exc:
            print_error(f"Failed to reload config: {exc}")
        return

    # Auto-reload before showing so info is always fresh
    _reload_backend_config(client)

    try:
        resp = client._client.get(f"{client.base_url}/api/v1/config")
        resp.raise_for_status()
        data = resp.json()
        print_info(f"Backend Model:        {data.get('model', '?')}")
        print_info(f"Backend API Key:      {'configured' if data.get('has_api_key') else 'NOT SET'}")
        print_info(f"Backend Custom Base:  {data.get('has_custom_base', False)}")
        print_info(f"Backend Max Tokens:   {data.get('max_tokens', '?')}")
        print_info(f"Backend Temperature:  {data.get('temperature', '?')}")
        print_info(f"Backend Max Turns:    {data.get('max_agent_turns', '?')}")
    except Exception as exc:
        print_error(str(exc))


def handle_reset(args: list[str], client: "APIClient") -> None:
    from cli.harness import get_runtime

    runtime = get_runtime(client)
    runtime.reset_conversation()
    print_success("Conversation cleared. Next prompt starts a fresh agent thread.")


def handle_clear(args: list[str], client: "APIClient") -> None:
    import os
    os.system("cls" if os.name == "nt" else "clear")


def handle_exit(args: list[str], client: "APIClient") -> None:
    """Placeholder so /exit shows in autocomplete. The actual exit is handled in
    execute_command (which intercepts /exit and returns False before dispatch)."""
    return None


def handle_details(args: list[str], client: "APIClient") -> None:
    from cli.harness import get_runtime

    transcript = get_runtime(client).transcript
    if args:
        try:
            mode = transcript.set_detail_mode(args[0].lower())
        except ValueError as exc:
            print_error(str(exc))
            return
    else:
        mode = transcript.cycle_detail_mode()
    print_success(f"Tool detail mode: {mode}")


def _read_artifact_text(client: "APIClient", engagement_id: str, path: str) -> str | None:
    data = client.read_artifact(engagement_id, path, limit=200_000)
    if not data:
        return None
    for key in ("content", "text", "data"):
        value = data.get(key)
        if isinstance(value, str):
            return value
    return str(data)


def handle_tool(args: list[str], client: "APIClient") -> None:
    from cli.harness import get_runtime

    transcript = get_runtime(client).transcript
    if not args:
        print_tool_history(transcript)
        return

    rec = transcript.get(args[0])
    if rec is None:
        print_error(f"No tool call found for {args[0]}.")
        print_tool_history(transcript)
        return

    engagement_id = client.active_engagement_id
    stdout_text = None
    stderr_text = None
    if engagement_id and rec.stdout_path:
        stdout_text = _read_artifact_text(client, engagement_id, rec.stdout_path)
    if engagement_id and rec.stderr_path:
        stderr_text = _read_artifact_text(client, engagement_id, rec.stderr_path)

    print_tool_detail(rec, stdout_text=stdout_text, stderr_text=stderr_text)


def handle_chat(args: list[str], client: "APIClient") -> None:
    """Show this CLI session's own agent conversation. Lives entirely in the
    CLI's own Runner (agent_core/loop.py) now — there is no separate
    server-side thread to fetch, so this reflects exactly what your next
    prompt will see as context, no more and no less."""
    from cli.harness import get_runtime

    messages = get_runtime(client).conversation_messages()
    if not messages:
        print_info("No conversation yet in this session. Send a prompt first.")
        return
    limit = 12
    if args:
        try:
            limit = max(1, min(50, int(args[0])))
        except ValueError:
            print_error("Usage: /chat [message-count]")
            return
    shown = [m for m in messages if m.get("role") in ("user", "assistant") and m.get("content")]
    print_chat_history(shown, limit=limit)


def handle_reconnect(args: list[str], client: "APIClient") -> None:
    """Re-read .env and reconnect to a (possibly changed) backend URL."""
    import os

    from dotenv import load_dotenv

    # This command explicitly promises to re-read .env.  Override the values
    # loaded at process startup so edits made during the session take effect.
    load_dotenv(override=True)
    new_url = os.getenv("API_BASE_URL", "http://localhost:9000")
    old_url = client.base_url
    client.reconnect(base_url=new_url)
    print_success(f"Reconnected: {old_url} -> {new_url}")
    print_info("Engagement and agent context cleared; bind a target before the next tool run.")


def handle_profile(args: list[str], client: "APIClient") -> None:
    """Operator profile — your preferences the harness adapts to. Add your own,
    or review/approve preferences the LLM inferred from how you work."""
    sub = (args[0].lower() if args else "list")
    try:
        if sub == "add" and len(args) > 1:
            pref = " ".join(args[1:]).strip()
            client.add_operator_preference(pref)
            print_success(f"Added to your profile: {pref}")
            return
        if sub in ("list", "show"):
            data = client.operator_profile()
            profile = (data.get("profile") or "").strip()
            pending = data.get("pending", [])
            if profile:
                print_info("Your confirmed profile (the harness adapts to these):")
                print(profile)
            else:
                print_info(
                    "No operator profile yet. Add one with /profile add <preference>, or the LLM "
                    "proposes preferences (platform_remember_preference) that you approve here."
                )
            if pending:
                print_info(f"\nPending preferences ({len(pending)}) — /profile approve|reject <id>:")
                for p in pending:
                    line = f"  [{p['id']}] {p['preference']}"
                    if p.get("rationale"):
                        line += f"  (why: {p['rationale']})"
                    print(line)
        elif sub == "approve" and len(args) > 1:
            client.approve_operator_preference(args[1])
            print_success("Approved — added to your profile. It now shapes every engagement.")
        elif sub == "reject" and len(args) > 1:
            client.reject_operator_preference(args[1])
            print_info(f"Rejected preference {args[1]}.")
        else:
            print_info(
                "Usage: /profile add <preference> (goes live immediately) | "
                "/profile list | /profile approve <id> | /profile reject <id>"
            )
    except Exception as exc:  # noqa: BLE001 — surface the API error text
        print_error(_api_error_text(exc))


def handle_agent(args: list[str], client: "APIClient") -> None:
    """Prompt-defined flows/modes (no code): /agent (list) · /agent <name> (switch) ·
    /agent default (reset to full catalog). Define agents in .osprey/agents/<name>.md."""
    from agent_core.flows import load_agents
    from cli.harness import get_runtime

    runtime = get_runtime(client)
    agents = load_agents()
    active = runtime.active_agent
    active_name = active.name if active is not None else "default"

    if not args or args[0].lower() == "list":
        print_info(f"Active agent: {active_name}")
        if agents:
            print_info("Available agents:")
            for a in agents.values():
                print(f"  {a.name} — {a.description or '(no description)'}")
        print("  default — full tool catalog, base policy")
        if not agents:
            print_info(
                "Create one: .osprey/agents/<name>.md — frontmatter (description, tools, deny_tools), "
                "body = the mode's instructions. Example: a recon mode with `deny_tools: metasploit_*, hydra_*, sqlmap_*`."
            )
        return

    name = args[0].strip().lower()
    if name in ("default", "none", "reset"):
        runtime.set_agent(None)
        print_success("Switched to the default agent (full catalog). Fresh conversation.")
        return

    agent = agents.get(name)
    if agent is None:
        print_error(f"No agent '{name}'. Run /agent to list, or create .osprey/agents/{name}.md")
        return
    runtime.set_agent(agent)
    scope = ""
    if agent.allow_tools or agent.deny_tools:
        scope = f" — tools allow={agent.allow_tools or 'all'}, deny={agent.deny_tools or 'none'}"
    if agent.model:
        scope += f", model={agent.model}"
    print_success(f"Switched to agent '{agent.name}'{scope}. Fresh conversation; applies now.")
