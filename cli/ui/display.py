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


def print_background_event(source: str, event_type: str, data: dict[str, Any]) -> None:
    """Render one event from the persistent /agent/events stream — the fix for
    background pipeline/spawned-agent activity being invisible. `source` is
    "pipeline" (conductor lifecycle) or "agent:<role>" (a spawned phase
    agent's own tool calls); tagged with a `[role]` prefix so it's visually
    distinguishable from the current interactive turn's own output without
    looking like a different, disconnected thing."""
    label = f"[bold yellow][{source}][/]"
    if event_type == "tool_start":
        args = _format_tool_args(data.get("arguments", {}))
        suffix = f"({args})" if args else "()"
        console.print(f"{label} [bold cyan]▶[/] [bold]{data.get('tool_name', '?')}[/]{suffix}")
    elif event_type == "tool_end":
        success = data.get("success", False)
        duration = data.get("duration_seconds", 0)
        icon = "[green]✓[/]" if success else "[red]✗[/]"
        console.print(f"{label} {icon} [dim]{data.get('tool_name', '?')}[/] ({duration:.1f}s)")
    elif event_type in ("pipeline_launched", "phase_triggered", "recon_reopened"):
        detail = data.get("reason") or data.get("phase") or ""
        console.print(f"{label} [bold magenta]◆[/] {event_type}" + (f" — {detail}" if detail else ""))
    elif event_type in ("pipeline_complete", "pipeline_stop", "pipeline_cancelled", "pipeline_error"):
        console.print(f"{label} [bold]{event_type}[/]")
    elif event_type == "assistant":
        content = (data.get("content") or "").strip()
        if content:
            console.print(f"{label} [dim italic]{content[:200]}[/]")
    elif event_type == "error":
        console.print(f"{label} [bold red]✗[/] {data.get('message', 'error')}")


def print_commander_decision(data: dict[str, Any]) -> None:
    action = data.get("action", "")
    phase = data.get("next_phase") or ""
    reasoning = (data.get("reasoning") or "").strip()
    label = f"[bold magenta]◆ commander[/] {action}" + (f" → {phase}" if phase else "")
    console.print(label)
    if reasoning:
        console.print(f"    [dim]{reasoning[:200]}[/]")


def print_phase_report(phase: str, content: str) -> None:
    """Render an intermediate per-phase report as it streams in."""
    if not content.strip():
        return
    console.print()
    console.print(f"[bold cyan]── {phase} phase report ──[/]")
    console.print(Markdown(content))


def print_phase_done(data: dict[str, Any]) -> None:
    phase = data.get("phase", "?")
    ok = data.get("success", False)
    icon = "[green]✓[/]" if ok else "[yellow]∅[/]"
    calls = data.get("tool_calls")
    suffix = f" [dim]({calls} tool calls)[/]" if calls is not None else ""
    reason = data.get("reason")
    if reason:
        suffix += f" [dim]— {reason}[/]"
    console.print(f"{icon} [bold]{phase}[/] phase complete{suffix}")


def consume_agent_stream(stream: Iterator[tuple[str, dict[str, Any]]]) -> dict[str, Any] | None:
    """Render live agent events in the terminal (OpenCode-style). Returns final done payload."""
    final: dict[str, Any] | None = None
    last_phase_report = ""

    for event_type, data in stream:
        if event_type == "run_start":
            print_run_start(data)
        elif event_type in ("status",):
            print_agent_thinking(data.get("message", "Working..."))
        elif event_type == "commander_decision":
            print_commander_decision(data)
        elif event_type == "forced_continue":
            attempt = data.get("attempt", "?")
            mx = data.get("max", "?")
            print_agent_thinking(f"Open work remains — continuing ({attempt}/{mx})...")
        elif event_type == "tool_start":
            print_tool_start_live(data.get("tool_name", "?"), data.get("arguments", {}))
        elif event_type == "tool_end":
            print_tool_end_live(data.get("tool_name", "?"), data)
        elif event_type == "assistant":
            # Per-phase narration (phase=recon/network) is shown live; the final
            # phase="full" report is skipped here because the `done` payload
            # carries the same text and prints it once at the end.
            if data.get("phase") not in (None, "", "full"):
                content = data.get("content", "")
                last_phase_report = content
                print_phase_report(data.get("phase", ""), content)
        elif event_type == "phase_done":
            print_phase_done(data)
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
        # Avoid double-printing when the final report equals the last per-phase report we already rendered (single-phase runs).
        if response and response.strip() != last_phase_report.strip():
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


_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
    "none": "dim",
}


def print_findings(findings: list[dict[str, Any]]) -> None:
    """Flat, one-row-per-instance view. Prefer print_findings_grouped for a
    normal browse — this stays available for inspecting raw individual rows."""
    if not findings:
        print_info("No findings yet. Run a scan to discover vulnerabilities.")
        return
    table = Table(title="Findings", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="bold")
    table.add_column("Title")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Tool")
    for finding in findings:
        # The Finding schema's field is `claim_severity`, not `severity` —
        # reading the wrong key silently showed "info" for every finding
        # regardless of actual severity.
        severity = finding.get("claim_severity") or "info"
        table.add_row(
            finding.get("id", "-"),
            finding.get("title", "-"),
            finding.get("finding_type", "-"),
            Text(severity, style=_SEVERITY_STYLE.get(severity, "dim")),
            finding.get("source_tool", "-"),
        )
    console.print(table)


def print_findings_grouped(data: dict[str, Any]) -> None:
    """One row per distinct issue pattern — the same NSE script across many
    ports, or the same URL-crawl pattern across many paths, collapsed into
    one row with an affected-target count instead of dozens of near-
    identical rows. Worst severity and widest-affected first (server-sorted).
    """
    groups = data.get("groups") or []
    if not groups:
        print_info("No findings yet. Run a scan to discover vulnerabilities.")
        return
    table = Table(title="Findings (grouped)", show_header=True, header_style="bold cyan")
    table.add_column("Title")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    table.add_column("Affected")
    table.add_column("Tool")
    for g in groups:
        severity = g.get("severity") or "info"
        targets = g.get("affected_targets") or []
        shown = ", ".join(targets[:3])
        if len(targets) > 3:
            shown += f" (+{len(targets) - 3} more)"
        table.add_row(
            g.get("title", "-"),
            g.get("finding_type", "-"),
            Text(severity, style=_SEVERITY_STYLE.get(severity, "dim")),
            str(g.get("count", 0)),
            shown or "-",
            g.get("source_tool", "-"),
        )
    console.print(table)
    # total_groups/total_findings are the true totals BEFORE the display cap —
    # shown_groups can be less than total_groups even when nothing looks
    # truncated at a glance, so always compare against the real total, never
    # against len(groups) (which is capped and would silently under-report).
    total_findings = data.get("total_findings", 0)
    total_groups = data.get("total_groups", len(groups))
    shown_groups = len(groups)
    if shown_groups < total_groups:
        print_info(
            f"Showing {shown_groups} of {total_groups} distinct issue(s) "
            f"(from {total_findings} individual finding(s) total) — grouped by pattern, worst first. "
            "Search with /findings <keyword> to narrow, or /findings <keyword> --flat for raw instances."
        )
    else:
        print_info(
            f"{total_groups} distinct issue(s) from {total_findings} individual finding(s) — "
            "grouped by pattern. Search with /findings <keyword> --flat to see raw instances."
        )


def print_banner() -> None:
    banner = Text()
    banner.append("AI Pentest Platform", style="bold green")
    banner.append(" — CLI Operator\n", style="dim")
    banner.append("Type ", style="dim")
    banner.append("/help", style="bold cyan")
    banner.append(" for commands, or enter a prompt to interact with the agent.\n", style="dim")
    console.print(Panel(banner, border_style="green", padding=(0, 1)))
