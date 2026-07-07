from __future__ import annotations

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
    if "error" in data:
        print_error(data["error"])
        return
    if "response" in data:
        console.print(Markdown(data["response"]))
        return
    console.print(Panel(str(data), title="Response"))


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
    table.add_column("Description")
    for tool in tools:
        table.add_row(
            tool.get("name", "unknown"),
            tool.get("category", "-"),
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
    table.add_column("Status")
    for model in models:
        status = Text("active", style="green") if model.get("active") else Text("inactive", style="red")
        table.add_row(
            model.get("name", "unknown"),
            model.get("provider", "-"),
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
