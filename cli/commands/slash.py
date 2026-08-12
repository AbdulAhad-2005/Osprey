from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.ui.display import (
    consume_agent_stream,
    print_engagements,
    print_error,
    print_findings,
    print_health,
    print_info,
    print_models,
    print_success,
    print_tools,
)


def handle_help(args: list[str], client: "APIClient") -> None:
    commands = {
        "/help": "Show this help message",
        "/health": "Check backend service health",
        "/tools": "List tools (installed vs missing in your Kali/host)",
        "/models": "List supported LLM models",
        "/model": "Show active LLM model + key status",
        "/scan <target> [phase]": "Bind target + scan (phase: recon|network|full)",
        "/engage list": "List all engagements",
        "/engage new <target>": "Create a new engagement",
        "/engage set <id>": "Bind this session to an existing engagement",
        "/findings": "Show discovered findings for the active engagement",
        "/status": "Show current session status (auto-refreshes config)",
        "/config": "Show config (auto-refreshes from .env)",
        "/config reload": "Force backend to re-read .env",
        "/reconnect": "Re-read .env and reconnect to changed API_BASE_URL",
        "/reset": "Clear agent conversation memory for this CLI session",
        "/clear": "Clear the terminal screen",
        "/exit": "Exit the CLI",
    }
    print_info("Available commands:")
    for cmd, desc in commands.items():
        print_info(f"  {cmd:<28} {desc}")
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
    tools = client.list_tools()
    print_tools(tools)


def handle_models(args: list[str], client: "APIClient") -> None:
    models = client.list_models()
    print_models(models)


def handle_model(args: list[str], client: "APIClient") -> None:
    """Show active model info (auto-refreshes from .env)."""
    _reload_backend_config(client)
    try:
        resp = client._client.get(f"{client.base_url}/api/v1/models/active")
        resp.raise_for_status()
        data = resp.json()
        print_info(f"Model:       {data.get('model', '?')}")
        print_info(f"API Key:     {'configured' if data.get('has_api_key') else 'NOT SET'}")
        print_info(f"Custom Base: {data.get('has_custom_base', False)}")
        print_info(f"Max Tokens:  {data.get('max_tokens', '?')}")
        print_info(f"Temperature: {data.get('temperature', '?')}")
    except Exception as exc:
        print_error(str(exc))


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
        client._set_active_engagement(args[1])
        print_success(f"Active engagement set to: {args[1]}")
    else:
        print_info("Usage: /engage list | /engage new <target> | /engage set <engagement_id>")


def _bind_engagement(client: "APIClient", data: dict) -> None:
    """Store the active engagement from an engagement payload and report it."""
    engagement_id = data.get("id") or data.get("engagement_id")
    if not engagement_id:
        print_error(f"Engagement response had no id: {data}")
        return
    client._set_active_engagement(engagement_id)
    label = data.get("target") or engagement_id
    reused = data.get("reused", False)
    if reused:
        print_info(f"Reusing existing engagement {engagement_id} for {label}")
    else:
        print_success(f"Engagement bound: {engagement_id} for {label}")


def _api_error_text(exc: Exception) -> str:
    """Extract a readable message from backend HTTP errors (422 detail etc.)."""
    if isinstance(exc, httpx.HTTPStatusError):
        try:
            detail = exc.response.json()
        except (json.JSONDecodeError, ValueError):
            return f"Request failed: {exc.response.status_code}"
        if isinstance(detail, dict) and detail.get("detail"):
            inner = detail["detail"]
            if isinstance(inner, dict):
                error = inner.get("error") or ""
                analysis = inner.get("analysis") or {}
                hints = analysis.get("candidates") or analysis.get("suggestions") or []
                msg = f"Request failed: {error}"
                if hints:
                    msg += f" — did you mean: {', '.join(str(h) for h in hints[:5])}"
                return msg
            return f"Request failed: {inner}"
        return f"Request failed: {exc.response.status_code}"
    return str(exc)


_SCAN_PHASES = {"recon", "network", "full"}

_PHASE_PROMPTS = {
    "full": (
        "Run a full recon and network penetration test on {target}. "
        "Establish the attack surface, probe services, and report findings."
    ),
    "recon": (
        "Run passive + active reconnaissance on {target}. Map the full external "
        "attack surface — subdomains, live hosts, DNS/ASN, tech fingerprints, "
        "historical URLs, and public exposure — then report."
    ),
    "network": (
        "Run a network penetration test on {target}. Port/service scan, "
        "enumerate exposed services, and report findings."
    ),
}


def handle_scan(args: list[str], client: "APIClient") -> None:
    """Bind an engagement to the target and run the agent pipeline on it.

    Usage: /scan <target> [recon|network|full]  (phase defaults to full)
    """
    if not args:
        print_info("Usage: /scan <target> [recon|network|full]  (e.g. /scan example.com recon)")
        return

    phase = "full"
    if len(args) > 1 and args[-1].lower() in _SCAN_PHASES:
        phase = args[-1].lower()
        args = args[:-1]
    target = " ".join(args)

    try:
        data = client.compile_engagement_for_target(target)
        _bind_engagement(client, data)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return

    print_info(f"Scanning {target} (phase: {phase}) — the agent will report back when done.")
    stream = client.send_prompt_stream(
        _PHASE_PROMPTS[phase].format(target=target),
        engagement_id=client.active_engagement_id,
        phase=phase,
    )
    final = consume_agent_stream(stream)
    if final is None:
        print_error("Agent stream ended without a final response.")
    elif not final.get("success", True) and final.get("error"):
        print_error(final["error"])


def handle_findings(args: list[str], client: "APIClient") -> None:
    engagement_id = args[0] if args else client.active_engagement_id
    if engagement_id:
        findings = client.list_findings(engagement_id)
        if not findings:
            print_info(f"No findings yet for engagement {engagement_id}.")
    else:
        print_info("No engagement bound. Run /scan <target> or /engage new <target> first.")
        return
    print_findings(findings)


def _reload_backend_config(client: "APIClient") -> bool:
    """Trigger backend config reload from .env. Returns True on success."""
    try:
        client._client.post(f"{client.base_url}/api/v1/config/reload")
        return True
    except Exception:
        return False


def handle_status(args: list[str], client: "APIClient") -> None:
    # Auto-reload backend config first so status is always fresh
    _reload_backend_config(client)

    try:
        health = client.health()
        backend_status = "connected" if health.get("status") == "ok" else "degraded"
    except Exception:
        backend_status = "disconnected"

    print_info(f"Backend: {backend_status}")
    print_info(f"API URL:  {client.base_url}")

    active = client.active_engagement_id
    if active:
        print_info(f"Engagement: {active}")
    else:
        print_info("Engagement: none — run /scan <target> or /engage new <target>")

    # Show agent status
    try:
        resp = client._client.get(f"{client.base_url}/api/v1/agent/status")
        resp.raise_for_status()
        data = resp.json()
        print_info(f"Model:     {data.get('model', '?')}")
        print_info(f"Model OK:  {'yes' if data.get('model_active') else 'no — set LLM_API_KEY'}")
        print_info(f"Tools:     {data.get('tools_available', 0)} available")
    except Exception:
        pass


def handle_config(args: list[str], client: "APIClient") -> None:
    """Show config and optionally reload from .env."""
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
        print_info(f"Model:        {data.get('model', '?')}")
        print_info(f"API Key:      {'configured' if data.get('has_api_key') else 'NOT SET'}")
        print_info(f"Custom Base:  {data.get('has_custom_base', False)}")
        print_info(f"Max Tokens:   {data.get('max_tokens', '?')}")
        print_info(f"Temperature:  {data.get('temperature', '?')}")
        print_info(f"Max Turns:    {data.get('max_agent_turns', '?')}")
    except Exception as exc:
        print_error(str(exc))


def handle_reset(args: list[str], client: "APIClient") -> None:
    client.reset_conversation()
    print_success("Conversation cleared. Next prompt starts a fresh agent thread.")


def handle_clear(args: list[str], client: "APIClient") -> None:
    import os
    os.system("cls" if os.name == "nt" else "clear")


def handle_reconnect(args: list[str], client: "APIClient") -> None:
    """Re-read .env and reconnect to a (possibly changed) backend URL."""
    import os

    from dotenv import load_dotenv

    load_dotenv()
    new_url = os.getenv("API_BASE_URL", "http://localhost:9000")
    old_url = client.base_url
    client.reconnect(base_url=new_url)
    print_success(f"Reconnected: {old_url} -> {new_url}")


SLASH_COMMANDS: dict[str, tuple[str, "callable"]] = {
    "/help": ("Show help", handle_help),
    "/health": ("Check backend health", handle_health),
    "/tools": ("List MCP tools", handle_tools),
    "/models": ("List LLM models", handle_models),
    "/model": ("Show active model", handle_model),
    "/scan": ("Bind target + run full agent scan", handle_scan),
    "/engage": ("Manage engagements", handle_engagements),
    "/findings": ("Show findings", handle_findings),
    "/status": ("Session status", handle_status),
    "/config": ("Show configuration", handle_config),
    "/reconnect": ("Re-read .env and reconnect to backend", handle_reconnect),
    "/reset": ("Clear agent conversation", handle_reset),
    "/clear": ("Clear screen", handle_clear),
}


def execute_command(command_line: str, client: "APIClient") -> bool:
    """Execute a slash command. Returns False if the user wants to exit."""
    parts = command_line.strip().split()
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd == "/exit":
        return False

    if cmd in SLASH_COMMANDS:
        _, handler = SLASH_COMMANDS[cmd]
        handler(args, client)
    else:
        print_error(f"Unknown command: {cmd}. Type /help for available commands.")

    return True
