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
        "/models": "List configured LLM models",
        "/scan <target>": "Start a scan against a target",
        "/engage list": "List all engagements",
        "/engage new <target>": "Create a new engagement",
        "/findings": "Show discovered findings",
        "/status": "Show current session status",
        "/config": "Show current configuration",
        "/clear": "Clear the terminal screen",
        "/exit": "Exit the CLI",
    }
    print_info("Available commands:")
    for cmd, desc in commands.items():
        print_info(f"  {cmd:<28} {desc}")


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
    print_findings(findings)


def handle_status(args: list[str], client: "APIClient") -> None:
    try:
        health = client.health()
        backend_status = "connected" if health.get("status") == "ok" else "degraded"
    except Exception:
        backend_status = "disconnected"

    print_info(f"Backend: {backend_status}")
    print_info(f"API URL:  {client.base_url}")


def handle_config(args: list[str], client: "APIClient") -> None:
    print_info(f"API_BASE_URL: {client.base_url}")


def handle_clear(args: list[str], client: "APIClient") -> None:
    import os
    os.system("cls" if os.name == "nt" else "clear")


SLASH_COMMANDS: dict[str, tuple[str, "callable"]] = {
    "/help": ("Show help", handle_help),
    "/health": ("Check backend health", handle_health),
    "/tools": ("List MCP tools", handle_tools),
    "/models": ("List LLM models", handle_models),
    "/engage": ("Manage engagements", handle_engagements),
    "/findings": ("Show findings", handle_findings),
    "/status": ("Session status", handle_status),
    "/config": ("Show configuration", handle_config),
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
