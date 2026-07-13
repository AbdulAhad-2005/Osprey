from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.ui.display import (
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
        "/tools": "List available MCP tools",
        "/models": "List supported LLM models",
        "/model": "Show active LLM model",
        "/scan <target>": "Start a scan against a target",
        "/engage list": "List all engagements",
        "/engage new <target>": "Create a new engagement",
        "/findings": "Show discovered findings",
        "/status": "Show current session status (auto-refreshes config)",
        "/config": "Show config (auto-refreshes from .env)",
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
    """Show active model info."""
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
    if not args:
        engagements = client.list_engagements()
        print_engagements(engagements)
    elif args[0] == "list":
        engagements = client.list_engagements()
        print_engagements(engagements)
    elif args[0] == "new" and len(args) >= 2:
        target = args[1]
        try:
            data = client.create_engagement({"target": target})
            print_success(f"Engagement created: {data.get('id', 'unknown')} for target {target}")
        except Exception as exc:
            print_error(str(exc))
    else:
        print_info("Usage: /engage list | /engage new <target>")


def handle_findings(args: list[str], client: "APIClient") -> None:
    engagement_id = args[0] if args else None
    findings = client.list_findings(engagement_id)
    if not findings and not engagement_id:
        print_info("No findings yet. Run a pentest to discover findings.")
        print_info("Tip: Findings are stored per-session. Start with: pentest> <target URL>")
    else:
        print_findings(findings)


def handle_status(args: list[str], client: "APIClient") -> None:
    try:
        health = client.health()
        backend_status = "connected" if health.get("status") == "ok" else "degraded"
    except Exception:
        backend_status = "disconnected"

    print_info(f"Backend: {backend_status}")
    print_info(f"API URL:  {client.base_url}")

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
        print_info(f"\nTo reload after editing .env: /config reload")
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
    from dotenv import load_dotenv, find_dotenv
    load_dotenv()
    import os
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
