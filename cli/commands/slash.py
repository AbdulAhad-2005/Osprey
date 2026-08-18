from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.ui.display import (
    console,
    consume_agent_stream,
    print_engagements,
    print_error,
    print_findings,
    print_findings_grouped,
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
        "/scan [target] [phase] [--mcp|--engine] [--include-low-confidence]": (
            "Bind target + scan. --mcp = LLM-driven (default); "
            "--engine = autonomous trigger-graph pipeline, no LLM. Prompts if omitted. "
            "--include-low-confidence (engine mode) also scans low-confidence origin "
            "candidates the engine holds back by default."
        ),
        "/engage list": "List all engagements",
        "/engage new <target>": "Create a new engagement",
        "/engage set <id>": "Bind this session to an existing engagement",
        "/findings [keyword] [--all] [--flat]": (
            "Show findings, grouped by issue pattern (noise excluded; --all shows everything; --flat = one row per instance)"
        ),
        "/report [--engagement <id>]": (
            "Write a Markdown recon report (seed -> sisters -> subdomains -> IPs -> ports/services/tech, WHOIS/OSINT, vulns) to ./reports/"
        ),
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


_SCAN_MODES = {"mcp", "engine"}


def handle_scan(args: list[str], client: "APIClient") -> None:
    """Bind an engagement to the target and run either the LLM-driven agent
    pipeline (mcp mode) or the autonomous trigger-graph engine (engine mode,
    no LLM involved — Nessus-style: subdomains/sisters -> IPs -> CDN/origin
    -> subnet pivot -> ports -> services -> OSINT, run to a fixpoint).

    Usage: /scan [target] [recon|network|full] [--mcp|--engine]
    Missing target or mode are asked for interactively.
    """
    mode = ""
    if "--mcp" in args:
        mode = "mcp"
        args = [a for a in args if a != "--mcp"]
    elif "--engine" in args:
        mode = "engine"
        args = [a for a in args if a != "--engine"]

    include_low_confidence = "--include-low-confidence" in args
    args = [a for a in args if a != "--include-low-confidence"]

    phase = "full"
    if args and args[-1].lower() in _SCAN_PHASES:
        phase = args[-1].lower()
        args = args[:-1]
    target = " ".join(args).strip()

    if not target:
        target = input("Target (domain or IP): ").strip()
        if not target:
            print_info("No target given — aborted.")
            return

    if not mode:
        choice = input("Mode — [1] mcp (LLM-driven, default) or [2] engine (autonomous, Nessus-style): ").strip()
        mode = "engine" if choice in ("2", "engine") else "mcp"

    try:
        data = client.compile_engagement_for_target(target)
        _bind_engagement(client, data)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return

    if mode == "engine":
        _run_engine_scan(client, target, include_low_confidence=include_low_confidence)
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


def _run_engine_scan(client: "APIClient", target: str, *, include_low_confidence: bool = False) -> None:
    """Engine mode: start the expansion job and poll to completion — a plain
    REST call the CLI drives directly, no LLM in the loop. The same backend
    endpoint a UI's "Scan" button or the MCP platform_expand tool would call —
    one engine, this is just one of its doors. Runs to completion: the engine
    stops when every stage has run to its fixpoint, and the operator (LLM or
    human) decides afterward whether to go over the surface again."""
    engagement_id = client.active_engagement_id
    if not engagement_id:
        print_error("No engagement bound.")
        return
    # Preflight: catch a dead execution backend (e.g. the Kali tools container
    # not started) up front, so the user gets one clear fix instead of watching
    # every tool in every stage report "(failed)".
    status = client.execution_status()
    if not status.get("ready", True):
        print_error(status.get("message", "Tool execution backend is not ready."))
        return
    if status.get("message"):
        print_info(status["message"])
    try:
        job = client.start_expansion_job(
            engagement_id, max_passes=10, include_low_confidence=include_low_confidence,
        )
    except Exception as exc:
        print_error(_api_error_text(exc))
        return

    job_id = job.get("job_id", "")
    print_info(f"Engine started (job {job_id}) — running the full recon/network pipeline on {target}.")
    print_info("Sister domains -> subdomains (tools + wordlist brute force) -> IPs -> CDN/origin "
                "detection -> subnet pivot -> ports -> services -> vuln scan -> OSINT, to a fixpoint.")

    status = job.get("status", "")
    last_progress = ""
    printed_results = 0
    try:
        with console.status("[bold cyan]Engine starting…[/]", spinner="dots") as spinner:
            while status in ("queued", "running"):
                try:
                    # Short wait_seconds keeps the live per-tool progress ticker
                    # responsive; long-polling still returns early on any change,
                    # so this isn't hammering the server.
                    job = client.poll_job(job_id, wait_seconds=3)
                except Exception as exc:
                    print_error(_api_error_text(exc))
                    return
                status = job.get("status", "")
                # results_log is append-only — print every entry we haven't shown
                # yet. Unlike the ephemeral `progress` string (which the next
                # in-flight update can overwrite before the next poll ever sees
                # it), nothing here can be missed regardless of poll timing.
                results_log = job.get("results_log") or []
                for line in results_log[printed_results:]:
                    console.print(f"  [green]{line}[/]")
                printed_results = len(results_log)

                progress = job.get("progress", "")
                if progress and progress != last_progress:
                    spinner.update(f"[bold cyan]{progress}[/]")
                    last_progress = progress
    except KeyboardInterrupt:
        print_error("Interrupted — findings gathered so far are saved. Review them with "
                    "/findings, or /report to export what was found so far.")
        return

    if status == "failed":
        print_error(f"Engine run failed: {job.get('error', 'unknown error')}")
        return

    if status == "cancelled":
        print_success("Engine stopped. Partial findings are saved.")
        print_info("Review them with /findings, or /report to export what was found so far.")
        return

    try:
        result = client.job_result(job_id)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return

    report = (result.get("result") or {})
    passes = report.get("passes") or []
    print_success(f"Engine finished — {len(passes)} pass(es), "
                  f"{'exhausted' if report.get('exhausted') else 'stopped at pass cap'}.")
    for p in passes:
        d = p.get("delta") or {}
        titles = p.get("new_finding_titles") or []
        sample = ", ".join(titles[:5]) + (f" (+{len(titles) - 5} more)" if len(titles) > 5 else "")
        print_info(
            f"  Pass {p.get('pass_number')}: +{d.get('new_nodes', 0)} assets, "
            f"+{d.get('new_edges', 0)} edges" + (f" — {sample}" if sample else "")
        )
    cand_count = report.get("new_candidate_count") or 0
    if cand_count:
        print_info(f"  +{cand_count} exploit candidate(s) — see /findings or platform_exploit_queue.")

    held_back = report.get("held_back_low_confidence") or []
    if held_back:
        console.print()
        console.print("[bold yellow]Held back — low-confidence origin candidates, not scanned:[/]")
        for item in held_back:
            console.print(f"  [yellow]•[/] {item}")
        console.print(
            f"  [dim]Re-run with[/] [bold]/scan {target} --engine --include-low-confidence[/] "
            "[dim]to scan these too.[/]"
        )

    print_info("Findings are already in memory — use /findings to review.")


def handle_findings(args: list[str], client: "APIClient") -> None:
    """Show findings for the active engagement, optionally filtered by keyword.

    Usage: /findings [keyword...] [--engagement <id>] [--all] [--flat]
    Grouped by default — the same issue firing on many host:port instances,
    or the same URL-crawl pattern across many paths, collapses into one row
    with an affected-target list instead of dozens of near-identical rows.
    Excludes unparsed/raw-output noise by default too (kept in the DB for
    evidence, just not shown). --all includes noise; --flat shows the raw
    one-row-per-instance view instead of grouping. Search by keyword (title,
    target, evidence, source tool) to cut through a large result set.
    """
    engagement_id = client.active_engagement_id
    if "--engagement" in args:
        idx = args.index("--engagement")
        if idx + 1 < len(args):
            engagement_id = args[idx + 1]
        args = args[:idx] + args[idx + 2 :]
    show_all = "--all" in args
    flat = "--flat" in args
    args = [a for a in args if a not in ("--all", "--flat")]
    query = " ".join(args).strip()

    if not engagement_id:
        print_info("No engagement bound. Run /scan <target> or /engage new <target> first.")
        return

    if flat:
        findings = client.list_findings(
            engagement_id, q=query, limit=500 if query else 100, exclude_noise=not show_all,
        )
        if not findings:
            if query:
                print_info(f"No findings matching '{query}' for engagement {engagement_id}.")
            else:
                print_info(f"No findings yet for engagement {engagement_id}.")
            return
        print_findings(findings)
        if not query and len(findings) == 100:
            print_info(
                "Showing the first 100 findings — this engagement may have more. "
                "Search with /findings <keyword>, e.g. /findings geo.tv or /findings exchange."
            )
        return

    data = client.list_findings_grouped(engagement_id, q=query, exclude_noise=not show_all)
    if not data.get("groups"):
        if query:
            print_info(f"No findings matching '{query}' for engagement {engagement_id}.")
        else:
            print_info(f"No findings yet for engagement {engagement_id}.")
        return
    print_findings_grouped(data)


def handle_report(args: list[str], client: "APIClient") -> None:
    """Write a human-readable recon report to a Markdown file: seed domain ->
    sister/associated domains -> subdomains (nested) -> IPs -> ports/services/
    tech, plus WHOIS/OSINT and a short vulnerability summary — the actual
    pipeline shape, not a flat findings table. A terminal table can't show
    this well; a saved file you can open, search, or hand to someone can.

    Usage: /report [--engagement <id>]
    """
    engagement_id = client.active_engagement_id
    if "--engagement" in args:
        idx = args.index("--engagement")
        if idx + 1 < len(args):
            engagement_id = args[idx + 1]

    if not engagement_id:
        print_info("No engagement bound. Run /scan <target> or /engage new <target> first.")
        return

    md = client.get_report_markdown(engagement_id)
    if md is None:
        print_error(f"Could not generate a report for engagement {engagement_id}.")
        return

    from datetime import datetime, timezone
    from pathlib import Path

    target_line = md.splitlines()[0] if md else ""
    target = target_line.replace("# Recon Report — ", "").strip() or engagement_id
    safe_target = "".join(c if c.isalnum() or c in ".-" else "_" for c in target)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    out_path = reports_dir / f"{safe_target}_{timestamp}.md"
    out_path.write_text(md, encoding="utf-8")

    print_success(f"Report written: {out_path.resolve()}")
    print_info("Open it in any Markdown viewer (VS Code, Obsidian, GitHub) to read it properly.")


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


def handle_exit(args: list[str], client: "APIClient") -> None:
    """Placeholder so /exit shows in autocomplete. The actual exit is handled in
    execute_command (which intercepts /exit and returns False before dispatch)."""
    return None


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
    "/report": ("Write a Markdown recon report to ./reports/", handle_report),
    "/status": ("Session status", handle_status),
    "/config": ("Show configuration", handle_config),
    "/reconnect": ("Re-read .env and reconnect to backend", handle_reconnect),
    "/reset": ("Clear agent conversation", handle_reset),
    "/clear": ("Clear screen", handle_clear),
    "/exit": ("Exit the CLI", handle_exit),
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
