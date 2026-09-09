from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from cli.branding import APP_NAME, APP_TAGLINE, CLI_COMMAND, LEGACY_CLI_COMMAND
from cli.session import (
    ToolRecord,
    get_detail_mode,
    tool_transcript,
)

console = Console()


def print_error(message: str) -> None:
    console.print(f"[bold red]Error:[/] {message}")


def print_success(message: str) -> None:
    console.print(f"[bold green]{message}[/]")


def print_info(message: str) -> None:
    console.print(f"[dim]{message}[/]")


def print_tool_call(tool_name: str, arguments: dict[str, Any]) -> None:
    args = ", ".join(
        f"{escape(str(k))}={escape(str(v))}" for k, v in arguments.items() if v
    )
    console.print(f"  [bold cyan]>[/] {escape(tool_name)}({args})")


def _format_tool_args(arguments: dict[str, Any], max_len: int = 80) -> str:
    parts = [f"{k}={v}" for k, v in arguments.items() if v not in (None, "", [], {})]
    text = ", ".join(parts)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _tool_label(rec: ToolRecord) -> str:
    prefix = f"#{rec.id:03d}"
    phase = f" {rec.phase}" if rec.phase else ""
    source = "" if rec.source == "commander" else f" [{rec.source}]"
    return f"{prefix}{phase}{source}"


def _status_style(success: bool | None) -> str:
    if success is None:
        return "cyan"
    return "green" if success else "red"


def _status_icon(success: bool | None) -> str:
    if success is None:
        return "▶"
    return "✓" if success else "✗"


def _quiet_tool(rec: ToolRecord, success: bool | None = None) -> bool:
    if get_detail_mode() == "verbose":
        return False
    return rec.display_quiet and success is not False


def _print_result_summary(rec: ToolRecord) -> None:
    detail_mode = get_detail_mode()
    if detail_mode == "compact":
        return
    if rec.finding_titles:
        label = "finding" if rec.success is not False else "record"
        for title in rec.finding_titles[:4]:
            console.print(f"      [green]{label}[/] [dim]{escape(title[:180])}[/]")
        remaining = len(rec.finding_titles) - 4
        if remaining > 0:
            console.print(f"      [dim]+ {remaining} more {label}(s); open /tool {rec.id}[/]")
        return
    if rec.stdout_path or rec.stderr_path:
        console.print(f"      [dim]output saved; open /tool {rec.id} for full stdout/stderr[/]")


def _print_preview_block(rec: ToolRecord) -> None:
    detail_mode = get_detail_mode()
    if detail_mode == "compact":
        return
    if detail_mode != "verbose" and rec.finding_titles:
        return
    legacy_lines = [line for line in rec.preview.strip().splitlines() if line.strip()]
    lines = legacy_lines if detail_mode == "verbose" else (rec.display_preview or legacy_lines)
    if not lines:
        return
    max_lines = 14 if detail_mode == "verbose" else (6 if rec.success is False else 3)
    for line in lines[:max_lines]:
        console.print(f"      [dim]{escape(line[:180])}[/]")


def print_tool_start_live(
    tool_name: str, arguments: dict[str, Any], data: dict[str, Any] | None = None
) -> None:
    payload = {"tool_name": tool_name, "arguments": arguments, **(data or {})}
    rec = tool_transcript.start(payload)
    if _quiet_tool(rec):
        return
    args = _format_tool_args(arguments)
    suffix = f" [dim]{escape(args)}[/]" if args else ""
    console.print(
        f"  [cyan]▶[/] [bold cyan]{_tool_label(rec)}[/] "
        f"[bold]{escape(tool_name)}[/]{suffix}"
    )


def print_tool_end_live(tool_name: str, data: dict[str, Any]) -> None:
    rec = tool_transcript.end({**data, "tool_name": tool_name})
    if _quiet_tool(rec, rec.success):
        return
    style = _status_style(rec.success)
    icon = _status_icon(rec.success)
    findings = f" · {len(rec.finding_titles)} finding(s)" if rec.finding_titles else ""
    output = " · output saved" if rec.stdout_path or rec.stderr_path else ""
    cache = " · cache" if rec.cache_hit else ""
    console.print(
        f"  [{style}]{icon}[/] [bold {style}]{_tool_label(rec)}[/] "
        f"[dim]{escape(tool_name)}[/] {rec.status_text} "
        f"[dim]({rec.duration_seconds:.1f}s{findings}{cache}{output}) · /tool {rec.id}[/]"
    )
    _print_result_summary(rec)
    _print_preview_block(rec)
    if get_detail_mode() == "verbose" and rec.command:
        console.print(f"      [dim]$ {escape(rec.command[:220])}[/]")


def _friendly_stream_error(message: str) -> str:
    lowered = message.lower()
    if "timeout" in lowered and ("litellm" in lowered or "openrouter" in lowered):
        return "LLM request timed out; Osprey will continue if the pipeline still has work."
    if "llm completion failed" in lowered:
        return "LLM completion failed; check /status for model/provider configuration."
    return message[:240]


def print_background_event(source: str, event_type: str, data: dict[str, Any]) -> None:
    """Render one event from the persistent /agent/events stream — the fix for
    background pipeline/spawned-agent activity being invisible. `source` is
    "pipeline" (conductor lifecycle) or "agent:<role>" (a spawned phase
    agent's own tool calls); tagged with a `[role]` prefix so it's visually
    distinguishable from the current interactive turn's own output without
    looking like a different, disconnected thing."""
    label = f"[bold yellow][{escape(source)}][/]"
    if event_type == "tool_start":
        rec = tool_transcript.start(data, source=source)
        if _quiet_tool(rec):
            return
        args = _format_tool_args(data.get("arguments", {}))
        suffix = f" [dim]{escape(args)}[/]" if args else ""
        console.print(
            f"{label} [cyan]▶[/] [bold cyan]{_tool_label(rec)}[/] "
            f"[bold]{escape(str(data.get('tool_name', '?')))}[/]{suffix}"
        )
    elif event_type == "tool_end":
        rec = tool_transcript.end(data, source=source)
        if _quiet_tool(rec, rec.success):
            return
        style = _status_style(rec.success)
        icon = _status_icon(rec.success)
        findings = f" · {len(rec.finding_titles)} finding(s)" if rec.finding_titles else ""
        output = " · output saved" if rec.stdout_path or rec.stderr_path else ""
        console.print(
            f"{label} [{style}]{icon}[/] [bold {style}]{_tool_label(rec)}[/] "
            f"[dim]{escape(rec.tool_name)}[/] {rec.status_text} "
            f"[dim]({rec.duration_seconds:.1f}s{findings}{output}) · /tool {rec.id}[/]"
        )
        _print_result_summary(rec)
        _print_preview_block(rec)
    elif event_type in ("pipeline_launched", "phase_triggered", "recon_reopened"):
        detail = data.get("reason") or data.get("phase") or ""
        console.print(f"{label} [bold magenta]◆[/] {event_type}" + (f" — {escape(str(detail))}" if detail else ""))
    elif event_type in ("pipeline_complete", "pipeline_stop", "pipeline_cancelled", "pipeline_error"):
        console.print(f"{label} [bold]{escape(event_type)}[/]")
    elif event_type == "assistant":
        content = (data.get("content") or "").strip()
        if content:
            console.print(f"{label} [dim italic]{escape(content[:200])}[/]")
    elif event_type == "error":
        console.print(
            f"{label} [bold red]✗[/] "
            f"{escape(_friendly_stream_error(str(data.get('message', 'error'))))}"
        )


def print_health(data: dict[str, Any]) -> None:
    table = Table(title="Service Health", show_header=True, header_style="bold cyan")
    table.add_column("Key", style="bold")
    table.add_column("Value")
    for key, value in data.items():
        table.add_row(key, str(value))
    console.print(table)


def print_tools(tools: list[dict[str, Any]], *, show_all: bool = False) -> None:
    if not tools:
        print_info("No tools registered yet. MCP servers will populate this list.")
        return

    missing = [t for t in tools if not t.get("installed")]
    installed_count = len(tools) - len(missing)
    color = "green" if not missing else "yellow"
    console.print(
        f"[bold {color}]{installed_count}/{len(tools)} tools installed[/bold {color}]"
        + (f" — {len(missing)} missing" if missing else "")
    )

    if not show_all:
        if missing:
            _print_missing_tools_table(missing)
        print_info("Run '/tools --all' to see every registered tool, installed or not.")
        return

    table = Table(title="Available Tools", show_header=True, header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Safety")
    table.add_column("Description")
    table.add_column("Install")
    for tool in tools:
        installed = tool.get("installed")
        status = Text("installed", style="green") if installed else Text("missing", style="yellow")
        table.add_row(
            tool.get("name", "unknown"),
            tool.get("category", "-"),
            status,
            tool.get("safety_level", "-"),
            tool.get("description", "-"),
            "-" if installed else (tool.get("install_hint") or "-"),
        )
    console.print(table)


def _print_missing_tools_table(missing: list[dict[str, Any]]) -> None:
    table = Table(title="Missing Tools", show_header=True, header_style="bold yellow")
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Install")
    for tool in missing:
        table.add_row(
            tool.get("name", "unknown"),
            tool.get("category", "-"),
            tool.get("install_hint") or f"Install {tool.get('executable', tool.get('name', ''))}.",
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


def print_tool_history(limit: int = 12) -> None:
    records = tool_transcript.recent(limit)
    if not records:
        print_info("No tool calls in this CLI session yet.")
        return
    table = Table(title="Recent Tool Calls", show_header=True, header_style="bold cyan", box=box.SIMPLE)
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("Tool", style="bold")
    table.add_column("Status", no_wrap=True)
    table.add_column("Time", justify="right", no_wrap=True)
    table.add_column("Args")
    for rec in records:
        status = Text(rec.status_text, style=_status_style(rec.success))
        table.add_row(
            f"#{rec.id}",
            rec.tool_name,
            status,
            f"{rec.duration_seconds:.1f}s" if rec.success is not None else "running",
            _format_tool_args(rec.arguments, max_len=72),
        )
    console.print(table)
    print_info("Open one with /tool <id>, for example /tool 3.")


def print_tool_detail(
    rec: ToolRecord,
    *,
    stdout_text: str | None = None,
    stderr_text: str | None = None,
) -> None:
    meta = Table.grid(expand=True)
    meta.add_column(ratio=1)
    meta.add_column(ratio=1)
    meta.add_row("Tool", rec.tool_name)
    meta.add_row("Status", rec.status_text)
    meta.add_row("Phase", rec.phase or "-")
    meta.add_row("Source", rec.source or "-")
    meta.add_row("Duration", f"{rec.duration_seconds:.2f}s")
    meta.add_row("Return code", "-" if rec.returncode is None else str(rec.returncode))
    if rec.cache_hit:
        meta.add_row("Cache", "hit")
    if rec.finding_titles:
        meta.add_row("Findings", ", ".join(rec.finding_titles[:8]))
    if rec.stdout_path:
        meta.add_row("Stdout path", rec.stdout_path)
    if rec.stderr_path:
        meta.add_row("Stderr path", rec.stderr_path)
    if rec.next_hint:
        meta.add_row("Next hint", rec.next_hint)
    console.print(Panel(meta, title=f"Tool #{rec.id}", border_style=_status_style(rec.success), box=box.ROUNDED))

    if rec.arguments:
        args = json_dump_pretty(rec.arguments)
        console.print(Panel(Syntax(args, "json", word_wrap=True), title="Arguments", border_style="cyan", box=box.ROUNDED))
    if rec.command:
        console.print(Panel(Syntax(rec.command, "bash", word_wrap=True), title="Command", border_style="cyan", box=box.ROUNDED))

    stdout_body = stdout_text if stdout_text is not None else rec.stdout
    stderr_body = stderr_text if stderr_text is not None else rec.stderr
    if stdout_body:
        console.print(Panel(Syntax(stdout_body.rstrip(), "text", word_wrap=True), title="Stdout", border_style="green", box=box.ROUNDED))
    elif rec.preview:
        console.print(Panel(escape(rec.preview.rstrip()), title="Preview", border_style="green", box=box.ROUNDED))
    if stderr_body:
        console.print(Panel(Syntax(stderr_body.rstrip(), "text", word_wrap=True), title="Stderr", border_style="red", box=box.ROUNDED))


def print_chat_history(messages: list[dict[str, Any]], *, limit: int = 12) -> None:
    if not messages:
        print_info("No Commander chat history for the active engagement yet.")
        return
    shown = messages[-limit:]
    for msg in shown:
        role = str(msg.get("role") or "?")
        content = str(msg.get("content") or "").strip()
        if not content:
            continue
        style = "cyan" if role == "user" else "green"
        title = "You" if role == "user" else "Commander"
        body = Markdown(content) if role == "assistant" else Text(content)
        console.print(Panel(body, title=title, border_style=style, box=box.ROUNDED))


def print_command_help(commands: dict[str, str]) -> None:
    table = Table(
        title=f"{APP_NAME} Commands",
        show_header=True,
        header_style="bold cyan",
        box=box.ROUNDED,
    )
    table.add_column("Command", style="bold cyan", no_wrap=True)
    table.add_column("What it does")
    for command, description in commands.items():
        table.add_row(command, description)
    console.print(table)
    print_info("Tip: run /details to cycle live output between compact, preview, and verbose.")


def json_dump_pretty(data: Any) -> str:
    import json

    return json.dumps(data, indent=2, sort_keys=True, default=str)


def print_banner() -> None:
    banner = Text()
    banner.append(APP_NAME, style="bold green")
    banner.append(f" — {APP_TAGLINE}\n", style="dim")
    banner.append("Type ", style="dim")
    banner.append("/help", style="bold cyan")
    banner.append(" for commands, ", style="dim")
    banner.append("/status", style="bold cyan")
    banner.append(" for session detail, or enter a prompt to talk to the Commander.\n", style="dim")
    banner.append(f"Launch from anywhere with `{CLI_COMMAND}`", style="dim")
    banner.append(f" (`{LEGACY_CLI_COMMAND}` still works as an alias).", style="dim")
    console.print(Panel(banner, border_style="green", box=box.ROUNDED, padding=(0, 1)))
