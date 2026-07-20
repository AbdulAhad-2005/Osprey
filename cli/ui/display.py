from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


def print_error(message: str) -> None:
    console.print(f"[bold red]Error:[/] {message}")


def print_success(message: str) -> None:
    console.print(f"[bold green]{message}[/]")


def print_info(message: str) -> None:
    console.print(f"[dim]{message}[/]")


def print_response(data: dict[str, Any]) -> None:
    if "error" in data and not data.get("response"):
        print_error(data["error"])
        return
    if "response" in data:
        # Show tool calls summary if present
        tool_calls = data.get("tool_calls", [])
        if tool_calls:
            print_tool_calls_summary(tool_calls, data.get("model", ""), data.get("duration_seconds", 0))
        console.print(Markdown(data["response"]))
        return
    console.print(Panel(str(data), title="Response"))


def print_agent_thinking(message: str) -> None:
    console.print(f"[dim italic]{message}[/]")


def print_tool_call(tool_name: str, arguments: dict[str, Any]) -> None:
    console.print(f"  [bold cyan]>[/] {tool_name}({', '.join(f'{k}={v}' for k, v in arguments.items() if v)})")


def _format_tool_args(arguments: dict[str, Any], max_len: int = 80) -> str:
    parts = [f"{k}={v}" for k, v in arguments.items() if v not in (None, "", [], {})]
    text = ", ".join(parts)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def print_run_start(data: dict[str, Any]) -> None:
    target = data.get("target") or "—"
    tools = data.get("tools", 0)
    model = data.get("model", "")
    phase = data.get("phase", "full")
    console.print(
        f"[bold green]▶[/] [bold]Agent run[/] "
        f"[dim]({phase} · target: {target} · {tools} tools · {model})[/]"
    )


def print_tool_start_live(tool_name: str, arguments: dict[str, Any]) -> None:
    args = _format_tool_args(arguments)
    suffix = f"({args})" if args else "()"
    console.print(f"  [bold cyan]▶[/] [bold]{tool_name}[/]{suffix}")


def print_tool_end_live(tool_name: str, data: dict[str, Any]) -> None:
    success = data.get("success", False)
    duration = data.get("duration_seconds", 0)
    icon = "[green]✓[/]" if success else "[red]✗[/]"
    status = "ok" if success else "failed"
    console.print(f"  {icon} [dim]{tool_name}[/] {status} [dim]({duration:.1f}s)[/]")
    preview = (data.get("preview") or "").strip()
    if preview:
        max_lines = 8 if not success else 4
        for line in preview.splitlines()[:max_lines]:
            console.print(f"    [dim]{line[:160]}[/]")


def print_stream_error(message: str) -> None:
    console.print(f"  [bold red]✗[/] {message}")


def consume_agent_stream(stream: Iterator[tuple[str, dict[str, Any]]]) -> dict[str, Any] | None:
    """Render live agent events in the terminal (OpenCode-style). Returns final done payload."""
    final: dict[str, Any] | None = None

    for event_type, data in stream:
        if event_type == "run_start":
            print_run_start(data)
        elif event_type == "status":
            print_agent_thinking(data.get("message", "Working..."))
        elif event_type == "tool_start":
            print_tool_start_live(data.get("tool_name", "?"), data.get("arguments", {}))
        elif event_type == "tool_end":
            print_tool_end_live(data.get("tool_name", "?"), data)
        elif event_type == "error":
            print_stream_error(data.get("message", "Unknown error"))
        elif event_type == "done":
            final = data

    if final:
        tool_calls = final.get("tool_calls", [])
        if tool_calls:
            print_tool_calls_summary(
                tool_calls,
                final.get("model", ""),
                final.get("duration_seconds", 0),
            )
        response = final.get("response", "")
        if response:
            console.print()
            console.print(Markdown(response))
    return final


def print_tool_calls_summary(tool_calls: list[dict[str, Any]], model: str, duration: float) -> None:
    if not tool_calls:
        return
    table = Table(title="Agent Execution Summary", show_header=True, header_style="bold cyan")
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Duration")
    for tc in tool_calls:
        status = Text("OK", style="green") if tc.get("success") else Text("FAIL", style="red")
        dur = f"{tc.get('duration_seconds', 0):.1f}s"
        table.add_row(tc.get("tool_name", "?"), status, dur)
    # Summary row
    total = len(tool_calls)
    ok = sum(1 for tc in tool_calls if tc.get("success"))
    console.print(table)
    console.print(f"[dim]Model: {model} | Tools: {ok}/{total} succeeded | Time: {duration:.1f}s[/]")


def print_health(data: dict[str, Any]) -> None:
    table = Table(title="Service Health", show_header=True, header_style="bold cyan")
    table.add_column("Key", style="bold")
    table.add_column("Value")
    for key, value in data.items():
        table.add_row(key, str(value))
    console.print(table)


def print_tools(tools: list[dict[str, Any]]) -> None:
    if not tools:
        print_info("No tools registered yet. MCP servers will populate this list.")
        return
    table = Table(title="Available Tools", show_header=True, header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Safety")
    table.add_column("Description")
    for tool in tools:
        installed = tool.get("installed")
        status = Text("installed", style="green") if installed else Text("missing", style="yellow")
        table.add_row(
            tool.get("name", "unknown"),
            tool.get("category", "-"),
            status,
            tool.get("safety_level", "-"),
            tool.get("description", "-"),
        )
    console.print(table)


def print_models(models: list[dict[str, Any]]) -> None:
    if not models:
        print_info("No models configured. Set LLM_API_KEY in .env to enable models.")
        return
    table = Table(title="Available Models", show_header=True, header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Provider")
    table.add_column("Description")
    table.add_column("Status")
    for model in models:
        status = Text("active", style="green") if model.get("active") else Text("inactive", style="dim")
        table.add_row(
            model.get("name", "unknown"),
            model.get("provider", "-"),
            model.get("description", "-"),
            status,
        )
    console.print(table)


def print_engagements(engagements: list[dict[str, Any]]) -> None:
    if not engagements:
        print_info("No engagements found. Create one with /engage new <target>.")
        return
    table = Table(title="Engagements", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="bold")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Created")
    for eng in engagements:
        table.add_row(
            eng.get("id", "-"),
            eng.get("target", "-"),
            eng.get("status", "-"),
            eng.get("created_at", "-"),
        )
    console.print(table)


def print_findings(findings: list[dict[str, Any]]) -> None:
    if not findings:
        print_info("No findings yet. Run a scan to discover vulnerabilities.")
        return
    table = Table(title="Findings", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="bold")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("CVSS")
    for finding in findings:
        severity = finding.get("severity", "info")
        severity_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(severity, "dim")
        table.add_row(
            finding.get("id", "-"),
            finding.get("title", "-"),
            Text(severity, style=severity_style),
            finding.get("status", "-"),
            str(finding.get("cvss_score", "-")),
        )
    console.print(table)


def print_banner() -> None:
    banner = Text()
    banner.append("AI Pentest Platform", style="bold green")
    banner.append(" — CLI Operator\n", style="dim")
    banner.append("Type ", style="dim")
    banner.append("/help", style="bold cyan")
    banner.append(" for commands, or enter a prompt to interact with the agent.\n", style="dim")
    console.print(Panel(banner, border_style="green", padding=(0, 1)))
