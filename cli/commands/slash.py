from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.session import (
    cycle_detail_mode,
    get_detail_mode,
    set_detail_mode,
    tool_transcript,
)
from cli.ui.display import (
    console,
    print_chat_history,
    print_command_help,
    print_engagements,
    print_error,
    print_findings,
    print_findings_grouped,
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
        "/scan [target] [phase] [--mcp|--engine] [--include-low-confidence]": (
            "Bind target + scan. --mcp = LLM-driven (default); "
            "--engine = autonomous trigger-graph pipeline, no LLM. "
            "--include-low-confidence (engine mode) also scans low-confidence origin "
            "candidates the engine holds back by default."
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
        "/promote": "No-LLM: cluster corroborated scanner-signal observations into findings",
        '/file <type> <obs_id,...> "<title>" [--severity ..] [--evidence ..]': "File an evidence-backed finding",
        "/finding fp <id> [--scope <glob>] [reason...]": "Mark a finding as noise (scoped to its own target by default)",
        "/fp list | remove <id>": "Audit/prune FP-cache patterns",
        "/world assets|related|incomplete|unexplained|conflicts [asset_id]": "Query the observation-backed graph",
        "/priority [--kinds ..] [--limit N] | phase vuln|exploit": "What's worth doing next (multi-factor, decay-aware)",
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
        "/chat": "Show the current engagement's Commander chat thread",
        "/details [compact|preview|verbose]": "Cycle or set live tool output detail level",
        "/status": "Show current session status (auto-refreshes config)",
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
        client.agent_runner = None  # rebuilt lazily with fresh CLIModelConfig; engagement kept
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
    backend's own .env has configured (see cli/agent/llm.py)."""
    from cli.agent.llm import CLIModelConfig, LLMNotConfiguredError

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


def _bind_engagement(client: "APIClient", data: dict) -> None:
    """Store the active engagement from an engagement payload and report it."""
    engagement_id = data.get("id") or data.get("engagement_id")
    if not engagement_id:
        print_error(f"Engagement response had no id: {data}")
        return
    client._set_active_engagement(
        engagement_id,
        target=str(data.get("target") or ""),
    )
    label = data.get("target") or engagement_id
    reused = data.get("reused", False)
    if reused:
        print_info(f"Reusing existing engagement {engagement_id} for {label}")
    else:
        print_success(f"Engagement bound: {engagement_id} for {label}")


def _take_flag(args: list[str], flag: str) -> tuple[str | None, list[str]]:
    """Extract `--flag value` from args, returning (value, remaining_args)."""
    if flag in args:
        idx = args.index(flag)
        if idx + 1 < len(args):
            return args[idx + 1], args[:idx] + args[idx + 2:]
        return None, args[:idx] + args[idx + 1:]
    return None, args


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
    if isinstance(exc, httpx.RequestError):
        return f"Could not reach the backend: {exc}"
    return str(exc)


_SCAN_PHASES = {"commander", "recon", "network", "vuln", "web", "exploit", "osint", "full"}

_PHASE_PROMPTS = {
    "commander": (
        "You are the Commander for {target}. Decide the best course: answer, run a "
        "single probe, or launch the full conductor pipeline in the background and "
        "steer it. Bind {target} and get to work."
    ),
    "full": (
        "Run a full penetration test on {target} via the conductor: recon is always "
        "the first/active phase; vuln and exploit unlock as real evidence accumulates. "
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
    "vuln": (
        "Run vulnerability analysis on {target} using the tech/services already "
        "discovered. Confirm real issues with proof, avoid false positives, and report."
    ),
    "web": (
        "Run web application testing on {target} — auth, session, business logic, "
        "config/headers, and injection surfaces — then report."
    ),
    "exploit": (
        "Attempt exploitation on {target} for evidence-backed candidates only, within "
        "authorized scope. Report what was confirmed and what was attempted."
    ),
    "osint": (
        "Run passive OSINT on {target} — people, credentials/breach exposure, "
        "document metadata, and public footprint — then report."
    ),
}


def handle_scan(args: list[str], client: "APIClient") -> None:
    """Bind an engagement to the target and run either the LLM-driven agent
    pipeline (mcp mode) or the autonomous trigger-graph engine (engine mode,
    no LLM involved — Nessus-style: subdomains/sisters -> IPs -> CDN/origin
    -> subnet pivot -> ports -> services -> OSINT, run to a fixpoint).

    Usage: /scan [target] [recon|network|full] [--mcp|--engine]
    Missing targets are asked for interactively; missing mode defaults to MCP.
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
        mode = "mcp"

    try:
        data = client.compile_engagement_for_target(target)
        _bind_engagement(client, data)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return

    if mode == "engine":
        _run_engine_scan(client, target, include_low_confidence=include_low_confidence)
        return

    from cli.commands.prompt import handle_prompt

    print_info(f"Scanning {target} (phase: {phase}) — the agent will report back when done.")
    handle_prompt(_PHASE_PROMPTS[phase].format(target=target), client)


def _poll_foreground_job(
    client: "APIClient",
    job: dict,
    *,
    label: str,
    spinner_text: str,
) -> dict | None:
    """Poll one background job while presenting it as foreground CLI work.

    Both deterministic scan commands use the same lifecycle: append-only result
    log, changing progress text, and server-side cancellation on Ctrl+C.  A
    transport failure does not imply that the server stopped the job, so retain
    and report its id rather than silently orphaning it.
    """
    job_id = str(job.get("job_id") or "")
    if not job_id:
        print_error(f"{label} did not return a job id.")
        return None

    status = str(job.get("status") or "")
    last_progress = ""
    printed_results = 0
    try:
        with console.status(f"[bold cyan]{spinner_text}[/]", spinner="dots") as spinner:
            while status in ("queued", "running"):
                try:
                    job = client.poll_job(job_id, wait_seconds=3)
                except Exception as exc:
                    print_error(_api_error_text(exc))
                    print_info(
                        f"Lost contact while {label.lower()} job {job_id} was running; "
                        "the server-side job may still be active. Reconnect and check its status."
                    )
                    return None
                status = str(job.get("status") or "")
                results_log = job.get("results_log") or []
                for line in results_log[printed_results:]:
                    console.print(f"  [green]{line}[/]")
                printed_results = len(results_log)

                progress = str(job.get("progress") or "")
                if progress and progress != last_progress:
                    spinner.update(f"[bold cyan]{progress}[/]")
                    last_progress = progress
    except KeyboardInterrupt:
        try:
            client.cancel_job(job_id)
            print_error(
                f"Interrupted — {label.lower()} job cancelled. Findings gathered so far are saved. "
                "Review them with /findings, or /report to export what was found so far."
            )
        except Exception:
            print_error(
                f"Interrupted — but the cancel request failed; {label.lower()} job {job_id} "
                "may still be running server-side. Findings gathered so far are saved "
                "(/findings, /report)."
            )
        return None
    return job


def _run_engine_scan(
    client: "APIClient", target: str, *, include_low_confidence: bool = False
) -> bool:
    """Engine mode: start the expansion job and poll to completion — a plain
    REST call the CLI drives directly, no LLM in the loop. The same backend
    endpoint a UI's "Scan" button or the MCP platform_expand tool would call —
    one engine, this is just one of its doors. Runs to completion: the engine
    stops when every stage has run to its fixpoint, and the operator (LLM or
    human) decides afterward whether to go over the surface again."""
    engagement_id = client.active_engagement_id
    if not engagement_id:
        print_error("No engagement bound.")
        return False
    # Preflight: catch a dead execution backend (e.g. the Kali tools container
    # not started) up front, so the user gets one clear fix instead of watching
    # every tool in every stage report "(failed)".
    status = client.execution_status()
    if not status.get("ready", True):
        print_error(status.get("message", "Tool execution backend is not ready."))
        return False
    if status.get("message"):
        print_info(status["message"])
    try:
        job = client.start_expansion_job(
            engagement_id, max_passes=10, include_low_confidence=include_low_confidence,
        )
    except Exception as exc:
        print_error(_api_error_text(exc))
        return False

    job_id = job.get("job_id", "")
    print_info(f"Engine started (job {job_id}) — running the full recon/network pipeline on {target}.")
    print_info("Sister domains -> subdomains (tools + wordlist brute force) -> IPs -> CDN/origin "
                "detection -> subnet pivot -> ports -> services -> vuln scan -> OSINT, to a fixpoint.")

    polled = _poll_foreground_job(
        client, job, label="Engine", spinner_text="Engine starting…"
    )
    if polled is None:
        return False
    job = polled
    status = job.get("status", "")

    if status == "failed":
        print_error(f"Engine run failed: {job.get('error', 'unknown error')}")
        return False

    if status == "cancelled":
        print_success("Engine stopped. Partial findings are saved.")
        print_info("Review them with /findings, or /report to export what was found so far.")
        return False

    try:
        result = client.job_result(job_id)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return False

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
    return True


def handle_fast_scan(args: list[str], client: "APIClient") -> None:
    """Deterministic, no-LLM, no-sister-domain fast scan.

    Usage: /fast-scan <domain> [--engine]

    whois -> direct subdomain enumeration (no domain_hunter/sister discovery)
    -> TLS cert SAN pass (merges in-scope SANs) -> resolve every host to IPs
    + CNAMEs -> classify CDN-edge vs origin IPs -> httpx live-probe -> nmap
    deep scan (service + OS detection, tuned min-rate, top ports) on origin
    IPs, a light 80/443 check on CDN-fronted IPs -> dangling-CNAME takeover
    check. Narrower and faster than /scan --engine (the full BFS breadth
    engine) — still passive/direct against the target's own DNS/TLS/IP
    surface, nothing else. `--engine` is accepted for consistency with
    /scan's flag but this command is inherently engine-only, no LLM mode
    exists for it.
    """
    args = [a for a in args if a != "--engine"]
    target = " ".join(args).strip()
    if not target:
        target = input("Target (domain): ").strip()
        if not target:
            print_info("No target given — aborted.")
            return

    try:
        data = client.compile_engagement_for_target(target)
        _bind_engagement(client, data)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return

    _run_fast_scan(client, target)


def _run_fast_scan(client: "APIClient", target: str) -> bool:
    engagement_id = client.active_engagement_id
    if not engagement_id:
        print_error("No engagement bound.")
        return False
    status = client.execution_status()
    if not status.get("ready", True):
        print_error(status.get("message", "Tool execution backend is not ready."))
        return False
    if status.get("message"):
        print_info(status["message"])

    try:
        job = client.start_fast_scan_job(engagement_id, target)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return False

    job_id = job.get("job_id", "")
    print_info(f"Fast scan started (job {job_id}) on {target}.")
    print_info("whois -> subdomains -> TLS SANs -> resolve IPs/CNAMEs -> classify CDN vs origin -> "
               "httpx live-probe -> nmap (full on origin, light on CDN edges) -> takeover check.")

    polled = _poll_foreground_job(
        client, job, label="Fast scan", spinner_text="Fast scan starting…"
    )
    if polled is None:
        return False
    job = polled
    status_str = job.get("status", "")

    if status_str == "failed":
        print_error(f"Fast scan failed: {job.get('error', 'unknown error')}")
        return False

    if status_str == "cancelled":
        print_success("Fast scan stopped. Partial findings are saved.")
        print_info("Review them with /findings, or /report to export what was found so far.")
        return False

    try:
        result = client.job_result(job_id)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return False

    report = (result.get("result") or {})
    subs = report.get("subdomains_found", 0)
    sans = report.get("sans_found", 0)
    ips = report.get("ips") or []
    origin_ips = report.get("origin_ips") or []
    cdn_ips = report.get("cdn_edge_ips") or []
    live_hosts = report.get("live_hosts", 0)
    cname_count = report.get("cname_count", 0)
    nmap_results = report.get("nmap_results") or []
    print_success(
        f"Fast scan finished — whois {'ok' if report.get('whois_ok') else 'failed'}, "
        f"{subs} subdomain(s) (+{sans} from TLS SANs), {len(ips)} IP(s) "
        f"({len(origin_ips)} origin, {len(cdn_ips)} CDN-edge), {live_hosts} live host(s)."
    )
    for r in nmap_results:
        titles = r.get("finding_titles") or []
        sample = ", ".join(titles[:5]) + (f" (+{len(titles) - 5} more)" if len(titles) > 5 else "")
        mark = "[green]ok[/]" if r.get("success") else "[red]failed[/]"
        tag = "[dim]cdn-edge, 80/443 only[/]" if r.get("scan_type") == "light" else ""
        print_info(f"  {r.get('ip')}: {mark} {tag}" + (f" — {sample}" if sample else ""))

    takeover_flags = report.get("takeover_flags") or []
    if takeover_flags:
        print_error(f"Subdomain takeover risk — {len(takeover_flags)} host(s) flagged (CNAMEs checked: {cname_count}):")
        for line in takeover_flags[:10]:
            print_info(f"  {line}")

    if report.get("stopped_reason") == "no_ips_resolved":
        print_info("No IPs resolved from the discovered hosts — nothing to port-scan.")

    print_info("Findings are already in memory — use /findings to review.")
    return True


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


def handle_finding(args: list[str], client: "APIClient") -> None:
    """Act on one finding by id — currently just false-positive marking.

    Usage: /finding fp <id> [--scope <glob>] [reason...]
    plans/harness/04-learning-fp-cache.md: appends a pattern learned from
    this finding's (type, title) and retracts it from the current
    engagement. By default the pattern scopes to THIS finding's own target
    only — it cannot suppress the same-titled signal on a different host by
    accident. Pass --scope "*" (or a glob like "*.internal.corp") only when
    you deliberately want to widen it. /fp list to review.
    """
    if not args or args[0].lower() != "fp" or len(args) < 2:
        print_info('Usage: /finding fp <id> [--scope "<glob>"] [reason...]')
        return
    finding_id = args[1]
    rest = list(args[2:])
    target_glob = ""
    if rest and rest[0] == "--scope" and len(rest) >= 2:
        target_glob = rest[1]
        rest = rest[2:]
    reason = " ".join(rest).strip()
    try:
        result = client.mark_finding_fp(finding_id, reason=reason, target_glob=target_glob)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            print_error(f"No finding with id '{finding_id}'.")
        else:
            print_error(f"Mark-FP failed: {exc}")
        return
    pattern = result.get("pattern") or {}
    print_success(
        f"Retracted finding {finding_id}. Learned FP-cache pattern "
        f"[{pattern.get('id')}] scope={pattern.get('target_glob')} "
        f"title_contains='{pattern.get('title_contains')}' — suppresses matching "
        "candidates on every future promotion. /fp list to review."
    )


def handle_fp(args: list[str], client: "APIClient") -> None:
    """FP-cache pattern audit — plans/harness/04-learning-fp-cache.md Step 4.

    Usage: /fp list | /fp remove <pattern_id>
    A bad mark shouldn't hide real findings forever — removing a pattern
    re-enables promotion for matching candidates on the next scan/replay.
    """
    sub = (args[0].lower() if args else "list")
    if sub == "list":
        data = client.list_fp_patterns()
        patterns = data.get("patterns", [])
        if not patterns:
            print_info("No FP-cache patterns yet. Mark noise with /finding fp <id> [reason].")
            return
        print_info(f"FP-cache patterns ({len(patterns)}):")
        for p in patterns:
            print(
                f"  [{p['id']}] scope={p['target_glob']} type={p.get('finding_type') or 'any'} "
                f"title_contains='{p['title_contains']}' reason='{p.get('reason', '')}'"
            )
    elif sub == "remove" and len(args) > 1:
        try:
            client.remove_fp_pattern(args[1])
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                print_error(f"No FP pattern with id '{args[1]}'.")
            else:
                print_error(f"Remove failed: {exc}")
            return
        print_success(f"Removed pattern {args[1]} — matching promotions are no longer suppressed.")
    else:
        print_info("Usage: /fp list | /fp remove <pattern_id>")


def _require_engagement(engagement_id: str | None) -> bool:
    if engagement_id:
        return True
    print_info("No engagement bound. Run /scan <target> or /engage new <target> first.")
    return False


def handle_observations(args: list[str], client: "APIClient") -> None:
    """List stored Observations — the structural facts parsers extracted
    (ports, services, technologies, scanner signals, injection points,
    credentials, …), each with an id.

    Usage: /observations [type] [--target <t>] [--engagement <id>] [--limit N]
    plans/harness/02-evidence-and-observation-layer.md: these are facts, not
    verdicts. Use an id shown here with /file to file an evidence-backed
    finding, or /promote for the no-LLM deterministic route.
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    target, args = _take_flag(args, "--target")
    limit_s, args = _take_flag(args, "--limit")
    obs_type = args[0] if args else ""
    if not _require_engagement(engagement_id):
        return
    try:
        data = client.list_observations(
            engagement_id, observation_type=obs_type, target=target or "", limit=int(limit_s) if limit_s else 200,
        )
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    items = data.get("observations") or []
    if not items:
        print_info(f"No observations yet for engagement {engagement_id}.")
        return
    print_info(f"Observations ({data.get('total', len(items))}):")
    for o in items:
        details = o.get("details") or {}
        label = details.get("title") or details.get("url") or details.get("hostname") or o.get("target", "")
        print(f"  id={o['id']} [{o['type']}] {label}  (via {o.get('source_tool', '')}, seen {o.get('occurrence_count', 1)}x)")


def handle_promote(args: list[str], client: "APIClient") -> None:
    """Deterministic, no-LLM promotion of scanner-signal observations to findings.

    Usage: /promote [--engagement <id>]
    plans/harness/03-earned-finding-pipeline.md Step 5: clusters SCANNER_SIGNAL
    observations, attaches whatever corroboration already exists, and files
    each through the same evidence law as /file. Never runs a destructive PoC —
    a single-source signal still becomes a finding, honestly graded HYPOTHESIS.
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not _require_engagement(engagement_id):
        return
    try:
        result = client.promote_observations(engagement_id)
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    findings = result.get("findings") or []
    by_conf: dict[str, int] = {}
    for f in findings:
        by_conf[f.get("confidence", "?")] = by_conf.get(f.get("confidence", "?"), 0) + 1
    print_success(f"Promoted {result.get('total', 0)} finding(s): {by_conf}")
    print_info("Use /findings to review.")


def handle_file(args: list[str], client: "APIClient") -> None:
    """File an evidence-backed finding — the only explicit (human/LLM) path
    into the finding store.

    Usage: /file <finding_type> <observation_id[,observation_id...]> "<title>"
           [--severity none|info|low|medium|high|critical]
           [--evidence corroboration|reproduction|verification|attestation]
           [--evidence-tool <tool>] [--evidence-detail "..."] [--desc "..."]
           [--tags a,b] [--target <t>] [--engagement <id>]
    plans/harness/03-earned-finding-pipeline.md: there is no confidence flag —
    you attach evidence, confidence_for computes it from what you attach.
    Omit --evidence for a bare signal (stays HYPOTHESIS unless >=2 independent
    tools already observed it).
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    severity, args = _take_flag(args, "--severity")
    evidence_kind, args = _take_flag(args, "--evidence")
    evidence_tool, args = _take_flag(args, "--evidence-tool")
    evidence_detail, args = _take_flag(args, "--evidence-detail")
    description, args = _take_flag(args, "--desc")
    tags_raw, args = _take_flag(args, "--tags")
    target, args = _take_flag(args, "--target")
    if not _require_engagement(engagement_id):
        return
    if len(args) < 3:
        print_info('Usage: /file <finding_type> <observation_id,...> "<title>" [--severity ...] [--evidence ...]')
        return
    finding_type, obs_ids_raw, *title_parts = args
    title = " ".join(title_parts).strip()
    observation_ids = [x.strip() for x in obs_ids_raw.split(",") if x.strip()]
    evidence_records = []
    if evidence_kind:
        evidence_records.append({"kind": evidence_kind, "source_tool": evidence_tool or "", "detail": evidence_detail or ""})
    tags = [t.strip() for t in (tags_raw or "").replace(",", " ").split() if t.strip()]
    try:
        result = client.file_finding(
            engagement_id=engagement_id, title=title, finding_type=finding_type,
            observation_ids=observation_ids, claim_severity=severity or "none",
            description=description or "", evidence_records=evidence_records,
            target=target or "", tags=tags,
        )
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    if result.get("suppressed"):
        print_info(f"Not filed — matches a known false-positive pattern: {result.get('suppressed_reason')}")
        return
    f = result.get("finding") or {}
    print_success(
        f"Filed finding id={f.get('id')} type={f.get('finding_type')} "
        f"confidence={f.get('confidence')} (computed) sev={f.get('claim_severity')}"
    )


def handle_world(args: list[str], client: "APIClient") -> None:
    """Query the world model — a read model over the observation-backed graph,
    not a new store.

    Usage: /world assets|related|incomplete|unexplained|conflicts [asset_id]
           [--type <asset_type>] [--engagement <id>]
      - assets: every asset node (optionally --type host|port|service|…).
      - related <asset_id>: what connects to it, closest first.
      - incomplete: HOST/SUBDOMAIN assets with no port evidence yet.
      - unexplained: observations not yet tied to any graph asset — raw
        material for /question or /hypothesis.
      - conflicts: assets with a disputed slot — both values kept, never
        silently picked.
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    asset_type, args = _take_flag(args, "--type")
    if not _require_engagement(engagement_id):
        return
    if not args:
        print_info("Usage: /world assets|related|incomplete|unexplained|conflicts [asset_id] [--type <t>]")
        return
    view = args[0].lower()
    items: list = []
    try:
        if view == "assets":
            data = client.world_model_assets(engagement_id, asset_type=asset_type or "")
            items = data.get("assets") or []
            for a in items[:80]:
                print(f"  {a['id']} confidence={a.get('confidence')} tools={a.get('source_tools')}")
        elif view == "related":
            if len(args) < 2:
                print_error("view='related' requires asset_id (e.g. 'host:example.com').")
                return
            data = client.world_model_related(engagement_id, args[1])
            items = data.get("related") or []
            for r in items[:80]:
                print(f"  {r['node_id']} ({r['hops']} hop via {r['via_relationship']})")
        elif view == "incomplete":
            data = client.world_model_incomplete(engagement_id)
            items = data.get("assets") or []
            for a in items[:80]:
                print(f"  {a['asset_id']}: {a['gap']}")
        elif view == "unexplained":
            data = client.world_model_unexplained(engagement_id)
            items = data.get("observations") or []
            for o in items[:80]:
                print(f"  {o['observation_id']} [{o['type']}] target={o['target']} via {o['source_tool']}")
        elif view == "conflicts":
            data = client.world_model_conflicts(engagement_id)
            items = data.get("conflicts") or []
            for c in items[:80]:
                vals = "; ".join(f"{slot}={[v['value'] for v in vs]}" for slot, vs in c["conflicts"].items())
                print(f"  {c['asset_id']}: {vals}")
        else:
            print_error("view must be one of assets|related|incomplete|unexplained|conflicts.")
            return
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    print_info(f"view={view} count={len(items)}")


def handle_attackpath(args: list[str], client: "APIClient") -> None:
    """Attack path — an ordered chain of (observation|asset|hypothesis) steps,
    each with a rationale for why it connects to the next.

    Usage:
      /attackpath propose "<title>" <step_kind> <step_ref_id> ["<rationale>"]
      /attackpath advance <path_id> [--status investigating|validated|dead]
                                     [--finding <id>]
                                     [--step <kind> <ref_id> ["<rationale>"]]
      /attackpath list [--all]
      /attackpath get <path_id>
    step_kind is observation|asset|hypothesis.
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not args:
        print_info("Usage: /attackpath propose|advance|list|get ...")
        return
    action, *rest = args
    action = action.lower()
    try:
        if action == "propose":
            if not _require_engagement(engagement_id):
                return
            if len(rest) < 3:
                print_error('propose requires: "<title>" <step_kind> <step_ref_id> ["<rationale>"]')
                return
            title, step_kind, step_ref_id, *rationale_parts = rest
            step = {"kind": step_kind.lower(), "ref_id": step_ref_id, "rationale": " ".join(rationale_parts)}
            data = client.propose_attack_path(engagement_id, title=title, steps=[step])
            print_success(f"Attack path proposed: id={data.get('id')} status={data.get('status')}")
        elif action == "advance":
            if not rest:
                print_error("advance requires <path_id>")
                return
            path_id, sub = rest[0], rest[1:]
            status, sub = _take_flag(sub, "--status")
            finding_id, sub = _take_flag(sub, "--finding")
            step = None
            if "--step" in sub:
                idx = sub.index("--step")
                step_parts = sub[idx + 1:]
                if len(step_parts) >= 2:
                    step = {"kind": step_parts[0].lower(), "ref_id": step_parts[1], "rationale": " ".join(step_parts[2:])}
            data = client.advance_attack_path(path_id, status=status or "", finding_id=finding_id or "", step=step)
            print_success(f"Attack path advanced: id={data.get('id')} status={data.get('status')} hops={len(data.get('steps') or [])}")
        elif action == "list":
            if not _require_engagement(engagement_id):
                return
            data = client.list_attack_paths(engagement_id, active_only="--all" not in rest)
            paths = data.get("attack_paths") or []
            if not paths:
                print_info("No active attack paths.")
                return
            for p in paths:
                print(f"  [{p['id']}] {p['status']}: {p['title']} ({len(p['steps'])} hop(s))")
        elif action == "get":
            if not rest:
                print_error("get requires <path_id>")
                return
            data = client.get_attack_path(rest[0])
            print(json.dumps(data, indent=2, default=str))
        else:
            print_error("action must be propose|advance|list|get.")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            print_error("No attack path with that id.")
        else:
            print_error(_api_error_text(exc))


def handle_question(args: list[str], client: "APIClient") -> None:
    """Open questions — a cheap reasoning scaffold, write freely, no approval
    needed.

    Usage:
      /question raise "<text>" [--asset <asset_id>]
      /question list [--all]
      /question answer <id> "<answer text>"
      /question dismiss <id>
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not args:
        print_info("Usage: /question raise|list|answer|dismiss ...")
        return
    action, *rest = args
    action = action.lower()
    try:
        if action == "raise":
            if not _require_engagement(engagement_id):
                return
            related, rest = _take_flag(rest, "--asset")
            text = " ".join(rest).strip()
            if not text:
                print_error('raise requires "<text>"')
                return
            data = client.raise_question(engagement_id, text=text, related_asset_id=related or "")
            print_success(f"Question raised: id={data.get('id')}: {data.get('text')}")
        elif action == "list":
            if not _require_engagement(engagement_id):
                return
            data = client.list_questions(engagement_id, open_only="--all" not in rest)
            items = data.get("questions") or []
            if not items:
                print_info("No open questions.")
                return
            for q in items:
                print(f"  [{q['id']}] {q['text']}")
        elif action == "answer":
            if len(rest) < 2:
                print_error('answer requires <id> "<answer text>"')
                return
            qid, *answer_parts = rest
            client.answer_question(qid, answer_text=" ".join(answer_parts))
            print_success(f"Question {qid} answered.")
        elif action == "dismiss":
            if not rest:
                print_error("dismiss requires <id>")
                return
            client.dismiss_question(rest[0])
            print_success(f"Question {rest[0]} dismissed.")
        else:
            print_error("action must be raise|list|answer|dismiss.")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            print_error("No question with that id.")
        else:
            print_error(_api_error_text(exc))


def handle_hypothesis(args: list[str], client: "APIClient") -> None:
    """Active hypotheses — an unresolved claim the reasoner is still testing,
    distinct from a Finding's evidence law (a hypothesis can be strengthened
    OR weakened).

    Usage:
      /hypothesis raise "<statement>" [observation_id...]
      /hypothesis list [--all]
      /hypothesis evidence <id> <observation_id> <true|false>
      /hypothesis resolve <id> <confirmed|refuted>
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not args:
        print_info("Usage: /hypothesis raise|list|evidence|resolve ...")
        return
    action, *rest = args
    action = action.lower()
    try:
        if action == "raise":
            if not _require_engagement(engagement_id):
                return
            if not rest:
                print_error('raise requires "<statement>"')
                return
            statement, *obs_ids = rest
            data = client.raise_hypothesis(engagement_id, statement=statement, supporting_observation_ids=obs_ids)
            print_success(f"Hypothesis raised: id={data.get('id')}: {data.get('statement')}")
        elif action == "list":
            if not _require_engagement(engagement_id):
                return
            data = client.list_hypotheses(engagement_id, active_only="--all" not in rest)
            items = data.get("hypotheses") or []
            if not items:
                print_info("No active hypotheses.")
                return
            for h in items:
                print(
                    f"  [{h['id']}] {h['statement']} (support={len(h.get('supporting_observation_ids') or [])} "
                    f"contra={len(h.get('contradicting_observation_ids') or [])})"
                )
        elif action == "evidence":
            if len(rest) < 3:
                print_error("evidence requires <id> <observation_id> <true|false>")
                return
            hid, oid, supports_raw = rest[0], rest[1], rest[2]
            data = client.add_hypothesis_evidence(hid, observation_id=oid, supports=supports_raw.lower() in ("true", "1", "yes"))
            print_success(
                f"Evidence attached. supporting={data.get('supporting_observation_ids')} "
                f"contradicting={data.get('contradicting_observation_ids')}"
            )
        elif action == "resolve":
            if len(rest) < 2:
                print_error("resolve requires <id> <confirmed|refuted>")
                return
            hid, status = rest[0], rest[1]
            client.resolve_hypothesis(hid, status=status.lower())
            print_success(f"Hypothesis {hid} resolved as {status.lower()}.")
        else:
            print_error("action must be raise|list|evidence|resolve.")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            print_error("No hypothesis with that id.")
        else:
            print_error(_api_error_text(exc))


def handle_priority(args: list[str], client: "APIClient") -> None:
    """What's worth doing next — a multi-factor score over the world model
    (observations, assets, questions, attack paths), ranked highest first.
    Never feeds back into a Finding's confidence (Plan 03's one law) — a low-
    confidence lead can still be the top priority.

    Usage: /priority [--kinds observation,asset,...] [--limit N] [--engagement <id>]
           /priority phase vuln|exploit [--engagement <id>]
    The phase form shows whether that area has crossed its unlock threshold
    (plans/harness/06-prioritization-engine.md Step 4 — replaces the old
    finding-count trigger) and the single highest-priority item driving it.
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not _require_engagement(engagement_id):
        return
    try:
        if args and args[0].lower() == "phase":
            if len(args) < 2:
                print_error("phase requires vuln|exploit")
                return
            data = client.phase_priority(engagement_id, args[1].lower())
            status = "UNLOCKED" if data.get("unlocked") else "locked"
            print_info(f"{data.get('phase')}: {status}")
            print(f"  {data.get('gate_reason', '')}")
            return
        kinds, args = _take_flag(args, "--kinds")
        limit_s, args = _take_flag(args, "--limit")
        data = client.top_priorities(engagement_id, kinds=kinds or "observation,asset,question,attack_path", limit=int(limit_s) if limit_s else 20)
        items = data.get("items") or []
        if not items:
            print_info("Nothing scored yet — no observations/assets/questions/attack paths.")
            return
        print_info(f"Top priorities ({len(items)}):")
        for it in items:
            print(f"  [{it['total']:.2f}] {it['item_kind']}:{it['type_key']} {it.get('label') or it.get('target', '')}")
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))


def handle_context(args: list[str], client: "APIClient") -> None:
    """The context packet — the exact same world-model-derived state the LLM
    gets injected fresh every turn (plans/harness/07-context-packet.md), so a
    human operator can see it too without needing an LLM in the loop.

    Usage: /context [--engagement <id>]
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not _require_engagement(engagement_id):
        return
    try:
        packet = client.get_context_packet(engagement_id)
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    print(packet)


def handle_skills(args: list[str], client: "APIClient") -> None:
    """Browse or query the skill library — plans/harness/08-skill-system-
    at-scale.md. Ranked retrieval, not a flat dump: at scale (hundreds of
    skills) "list everything" stops being useful, so `find` scores every
    skill against whatever you give it and returns the top matches.

    Usage:
      /skills                                    router-level index (cheap, always available)
      /skills list [--phase <phase>]              browse a phase, unranked
      /skills find [<query>] [--phase ..] [--tags a,b] [--mitre T1098] [--asset-type ..] [--limit N]
      /skills get <path-or-name>                  full text of one skill
    (Distinct from /skill, which reviews LLM-proposed learned skills.)
    """
    if not args or args[0].lower() == "list":
        phase, rest = _take_flag(args[1:] if args else [], "--phase")
        try:
            data = client.list_skills_index(phase=phase or "")
        except httpx.HTTPStatusError as exc:
            print_error(_api_error_text(exc))
            return
        items = data.get("skills") or []
        print_info(f"Skills ({data.get('count', len(items))}):")
        for it in items:
            print(f"  [{it.get('phase')}] {it.get('name')} — {it.get('description', '')[:100]}")
        return

    action, *rest = args
    action = action.lower()
    if action == "find":
        phase, rest = _take_flag(rest, "--phase")
        tags, rest = _take_flag(rest, "--tags")
        mitre, rest = _take_flag(rest, "--mitre")
        asset_type, rest = _take_flag(rest, "--asset-type")
        limit_s, rest = _take_flag(rest, "--limit")
        query = " ".join(rest).strip()
        try:
            data = client.find_skills(
                query=query, phase=phase or "", tags=tags or "", mitre=mitre or "",
                asset_type=asset_type or "", limit=int(limit_s) if limit_s else 8,
            )
        except httpx.HTTPStatusError as exc:
            print_error(_api_error_text(exc))
            return
        items = data.get("skills") or []
        if not items:
            print_info("No matching skills — try broader terms.")
            return
        print_info(f"Top {len(items)} matching skill(s):")
        for it in items:
            print(f"  [{it.get('phase')}] {it.get('name')} — {it.get('description', '')[:100]}")
        print_info("Use /skills get <name> for full text.")
    elif action == "get":
        if not rest:
            print_error("get requires <path-or-name>")
            return
        try:
            data = client.get_skill_file(rest[0])
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                print_error(f"No skill found matching '{rest[0]}'.")
            else:
                print_error(_api_error_text(exc))
            return
        print(f"# {data.get('path')} — {data.get('title')}\n")
        print(data.get("content") or "")
    else:
        print_info("Usage: /skills [list [--phase ..]] | find <query> ... | get <path-or-name>")


def handle_link(args: list[str], client: "APIClient") -> None:
    """Create an operator-named graph edge — cognition write-back.

    Usage: /link <source> <relation> <target> "<evidence>" [--confidence confirmed|likely|hypothesis]
    source/target: 'host:erp.x.com' or bare hostname/IP/URL. relation: free
    name (e.g. same_app_as, shares_auth_cookie). Non-confirmed becomes a
    hypothesis_* edge — not proof for COMPLETE/CRITICAL. evidence is
    required (why the link exists).
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    confidence, args = _take_flag(args, "--confidence")
    derived_from, args = _take_flag(args, "--derived-from")
    if not _require_engagement(engagement_id):
        return
    if len(args) < 4:
        print_error('Usage: /link <source> <relation> <target> "<evidence>"')
        return
    source, relation, target, *evidence_parts = args
    evidence = " ".join(evidence_parts).strip()
    try:
        data = client.graph_link(
            engagement_id=engagement_id, source=source, target=target, relation=relation,
            evidence=evidence, confidence=confidence or "likely", derived_from=derived_from or "",
        )
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    print_success(
        f"{data.get('source_id')} --{data.get('relationship')}--> {data.get('target_id')} "
        f"(confidence={data.get('confidence')} hypothesis={data.get('hypothesis')})"
    )


def handle_record(args: list[str], client: "APIClient") -> None:
    """Record a reasoned conclusion — no prior tool output backs it (an
    interpretation, a hand-verified fact). For a relationship use /link; for
    an open-ended hypothesis use /hypothesis raise.

    Usage: /record <finding_type> "<title>" "<evidence>" [--severity ..] [--desc ..] [--tags ..]
    There is no confidence flag — like /file, the evidence you give becomes
    an attestation and confidence_for computes confidence from it.
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    severity, args = _take_flag(args, "--severity")
    description, args = _take_flag(args, "--desc")
    tags_raw, args = _take_flag(args, "--tags")
    target, args = _take_flag(args, "--target")
    if not _require_engagement(engagement_id):
        return
    if len(args) < 3:
        print_error('Usage: /record <finding_type> "<title>" "<evidence>" [--severity ..] [--desc ..]')
        return
    finding_type, title, *evidence_parts = args
    evidence = " ".join(evidence_parts).strip()
    tags = [t.strip() for t in (tags_raw or "").replace(",", " ").split() if t.strip()]
    try:
        result = client.record_finding(
            engagement_id=engagement_id, title=title, evidence=evidence, finding_type=finding_type,
            claim_severity=severity or "none", description=description or "", target=target or "",
            tags=tags or ["operator_recorded"],
        )
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    if result.get("suppressed"):
        print_info(f"Not filed — matches a known false-positive pattern: {result.get('suppressed_reason')}")
        return
    f = result.get("finding") or {}
    print_success(
        f"Recorded finding id={f.get('id')} type={f.get('finding_type')} "
        f"confidence={f.get('confidence')} (computed) sev={f.get('claim_severity')}"
    )


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
    print_info(f"Details:  {get_detail_mode()}")

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
    recent = tool_transcript.recent(1)
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
    client.reset_conversation()
    tool_transcript.clear()
    print_success("Conversation cleared. Next prompt starts a fresh agent thread.")


def handle_clear(args: list[str], client: "APIClient") -> None:
    import os
    os.system("cls" if os.name == "nt" else "clear")


def handle_exit(args: list[str], client: "APIClient") -> None:
    """Placeholder so /exit shows in autocomplete. The actual exit is handled in
    execute_command (which intercepts /exit and returns False before dispatch)."""
    return None


def handle_details(args: list[str], client: "APIClient") -> None:
    if args:
        try:
            mode = set_detail_mode(args[0].lower())
        except ValueError as exc:
            print_error(str(exc))
            return
    else:
        mode = cycle_detail_mode()
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
    if not args:
        print_tool_history()
        return

    rec = tool_transcript.get(args[0])
    if rec is None:
        print_error(f"No tool call found for {args[0]}.")
        print_tool_history()
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
    CLI's own Runner (cli/agent/loop.py) now — there is no separate
    server-side thread to fetch, so this reflects exactly what your next
    prompt will see as context, no more and no less."""
    runner = getattr(client, "agent_runner", None)
    if runner is None or not runner.messages:
        print_info("No conversation yet in this session. Send a prompt first.")
        return
    limit = 12
    if args:
        try:
            limit = max(1, min(50, int(args[0])))
        except ValueError:
            print_error("Usage: /chat [message-count]")
            return
    shown = [m for m in runner.messages if m.get("role") in ("user", "assistant") and m.get("content")]
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


def _parse_skill_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Minimal `--- key: value ---` frontmatter parse (mirrors the backend)."""
    stripped = text.lstrip("﻿")
    if not stripped.startswith("---"):
        return {}, text
    lines = stripped.splitlines()
    meta: dict[str, str] = {}
    body_start = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            body_start = i + 1
            break
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            meta[k.strip()] = v.strip().strip('"').strip("'")
    if body_start is None:
        return {}, text
    return meta, "\n".join(lines[body_start:]).lstrip("\n")


def handle_skill(args: list[str], client: "APIClient") -> None:
    """Operator surface for the learned-skills tier: add your own, or review/approve
    the LLM's proposals."""
    sub = (args[0].lower() if args else "list")
    try:
        if sub == "add" and len(args) > 1:
            import os
            path = " ".join(args[1:]).strip().strip('"')
            if not os.path.isfile(path):
                print_error(f"File not found: {path}")
                return
            meta, body = _parse_skill_frontmatter(open(path, encoding="utf-8").read())
            if not meta.get("phase") or not meta.get("description"):
                print_error(
                    "The .md needs frontmatter with at least `phase:` and `description:` "
                    "(and ideally `name:`). See any file under skills/ for the format."
                )
                return
            payload = {
                "name": meta.get("name") or os.path.splitext(os.path.basename(path))[0],
                "phase": meta["phase"],
                "description": meta["description"],
                "content": body,
                "tags": [t.strip() for t in meta.get("tags", "").strip("[]").split(",") if t.strip()],
            }
            r = client.add_learned_skill(payload)
            print_success(f"Added — active at skills/{r.get('path')} ({r.get('phase')} phase).")
            return
        if sub == "list":
            data = client.list_learned_skills()
            props = data.get("proposals", [])
            active = data.get("active", [])
            if not props and not active:
                print_info(
                    "No learned skills yet. When enable_learned_skills=true, the LLM proposes "
                    "them (platform_propose_skill); you approve them here."
                )
                return
            if props:
                print_info(f"Pending proposals ({len(props)}) — /skill show <id>, then /skill approve|reject <id>:")
                for p in props:
                    print(f"  [{p['id']}] [{p['phase']}] {p['name']} — {p['description']}")
                    similar = p.get("similar_to") or []
                    if similar:
                        top = ", ".join(f"{s['skill']} ({s['score']})" for s in similar[:3])
                        print(f"      similar to: {top}")
            if active:
                print_info(f"Active learned skills ({len(active)}):")
                for a in active:
                    print(f"  {a['name']} [{a['phase']}] — {a['description']}")
        elif sub == "show" and len(args) > 1:
            data = client.list_learned_skills()
            p = next((x for x in data.get("proposals", []) if x["id"] == args[1]), None)
            if not p:
                print_error(f"No pending proposal with id {args[1]}.")
                return
            print(f"[{p['phase']}] {p['name']}\n{p['description']}\n\n{p['content']}")
            if p.get("evidence"):
                print(f"\nGrounded in: {p['evidence']}")
            similar = p.get("similar_to") or []
            if similar:
                top = ", ".join(f"{s['skill']} ({s['score']})" for s in similar)
                print(f"\nSimilar to: {top} — weigh novelty before approving.")
        elif sub == "approve" and len(args) > 1:
            r = client.approve_learned_skill(args[1])
            print_success(f"Approved — now active at skills/{r.get('path')} ({r.get('phase')} phase).")
        elif sub == "reject" and len(args) > 1:
            client.reject_learned_skill(args[1])
            print_info(f"Rejected proposal {args[1]}.")
        else:
            print_info(
                "Usage: /skill add <file.md>  (author your own, goes live immediately) | "
                "/skill list | /skill show <id> | /skill approve <id> | /skill reject <id>"
            )
    except Exception as exc:  # noqa: BLE001 — surface the API error text
        print_error(_api_error_text(exc))


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


def _reset_agent_runner(client: "APIClient") -> None:
    """Drop the cached Runner so the next prompt rebuilds it with the active
    agent's system-prompt overlay, tool scope, and model — a mode switch starts
    a fresh conversation so the mode fully applies."""
    if getattr(client, "agent_runner", None) is not None:
        client.agent_runner = None


def handle_agent(args: list[str], client: "APIClient") -> None:
    """Prompt-defined flows/modes (no code): /agent (list) · /agent <name> (switch) ·
    /agent default (reset to full catalog). Define agents in .osprey/agents/<name>.md."""
    from cli.agent.flows import load_agents

    agents = load_agents()
    active = getattr(client, "active_agent", None)
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
        client.active_agent = None
        _reset_agent_runner(client)
        print_success("Switched to the default agent (full catalog). Fresh conversation.")
        return

    agent = agents.get(name)
    if agent is None:
        print_error(f"No agent '{name}'. Run /agent to list, or create .osprey/agents/{name}.md")
        return
    client.active_agent = agent
    _reset_agent_runner(client)
    scope = ""
    if agent.allow_tools or agent.deny_tools:
        scope = f" — tools allow={agent.allow_tools or 'all'}, deny={agent.deny_tools or 'none'}"
    if agent.model:
        scope += f", model={agent.model}"
    print_success(f"Switched to agent '{agent.name}'{scope}. Fresh conversation; applies now.")


SLASH_COMMANDS: dict[str, tuple[str, "callable"]] = {
    "/help": ("Show help", handle_help),
    "/health": ("Check backend health", handle_health),
    "/tools": ("List MCP tools", handle_tools),
    "/models": ("List LLM models", handle_models),
    "/model": ("Show active model, or `/model reload` to re-read .env in place", handle_model),
    "/scan": ("Bind target + run full agent scan", handle_scan),
    "/fast-scan": ("Deterministic no-LLM scan: whois+subs+SANs+IPs+CDN-classify+httpx+nmap+takeover", handle_fast_scan),
    "/engage": ("Manage engagements", handle_engagements),
    "/findings": ("Show findings", handle_findings),
    "/finding": ("Act on one finding by id (fp <id> [reason])", handle_finding),
    "/fp": ("FP-cache patterns: list | remove <id>", handle_fp),
    "/observations": ("List stored Observations (structural facts, not verdicts)", handle_observations),
    "/promote": ("No-LLM: promote corroborated scanner-signal observations to findings", handle_promote),
    "/file": ("File an evidence-backed finding (no confidence flag — evidence computes it)", handle_file),
    "/world": ("Query the world model: assets|related|incomplete|unexplained|conflicts", handle_world),
    "/priority": ("What's worth doing next: top items, or phase <vuln|exploit> unlock status", handle_priority),
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
    "/chat": ("Show Commander chat history", handle_chat),
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
    from cli.agent.flows import expand_command, load_commands

    cmds = load_commands()
    name = cmd.lstrip("/")
    if name in cmds:
        from cli.commands.prompt import handle_prompt

        handle_prompt(expand_command(cmds[name].template, args), client)
        return True

    print_error(f"Unknown command: {cmd}. Type /help for available commands.")
    return True
