from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.commands.scan_shared import (
    _api_error_text,
    _bind_engagement,
    _run_engine_scan,
    _run_investigation_events,
)
from cli.ui.display import (
    console,
    print_error,
    print_info,
    print_success,
)



_SCAN_PHASES = {"recon", "network", "vuln", "web", "exploit", "osint", "full"}

_PHASE_PROMPTS = {
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
    """Bind an engagement and run the harness investigation driver.

    Three real modes, not one flag bolted onto another:
    - default: the model drives every typed tool itself (the free ReAct
      loop) — full LLM judgment, full token cost, for when you want to watch
      or steer every step.
    - ``--engine``: the deterministic, no-LLM opportunity engine — zero LLM
      tokens, the obvious mechanical pentest work (subdomains, DNS, ports,
      services, tech-triggered vuln scanners) runs itself to fixpoint.
    - ``--supervised``: the deterministic engine drives itself exactly like
      ``--engine``, but an LLM checks in at bounded checkpoints (not every
      step) with full, unrestricted tool access — it can investigate,
      redirect, or do nothing, same judgment as driving directly, just
      consulted only when there's actually something worth a decision.
      This is the default division of labor for "save tokens on the obvious
      steps, keep LLM judgment for what needs it."

    Usage: /scan [target] [recon|network|full] [--mcp|--engine|--supervised] [--fresh]
    Missing targets are asked for interactively; ``recon``/``network``/etc.
    single-phase scans always use the free ReAct loop (--engine/--supervised
    only apply to a full scan). ``--fresh`` starts a brand-new engagement
    instead of silently reusing an existing one for this target — without
    it, an existing engagement (and everything already known about the
    target) is reused, same as always.
    """
    mode = ""
    if "--mcp" in args:
        mode = "mcp"
        args = [a for a in args if a != "--mcp"]
    elif "--supervised" in args:
        mode = "supervised"
        args = [a for a in args if a != "--supervised"]
    elif "--engine" in args:
        mode = "engine"
        args = [a for a in args if a != "--engine"]

    force_new = "--fresh" in args
    args = [a for a in args if a != "--fresh"]

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

    try:
        data = client.compile_engagement_for_target(target, force_new=force_new)
        _bind_engagement(client, data)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return

    if mode in {"engine", "supervised"} and phase == "full":
        _run_engine_scan(client, target, supervised=mode == "supervised")
        return
    if mode in {"engine", "supervised"}:
        print_info(f"--{mode} applies to a full scan only; running the targeted {phase} agent instead.")
    # Default path: the model drives the typed recon/vuln/exploit tools
    # directly — the same free ReAct loop the single-phase commands already
    # use — guided by AGENTS.md's methodology and platform_priority/
    # platform_context as advisory signals. This is NOT routed through the
    # opportunity-picker: an LLM should reason tool-by-tool like it already
    # does for vuln/exploit, never be reduced to choosing one opaque id per
    # turn from a server menu.
    label = "targeted" if phase != "full" else "full"
    print_info(f"Running the {label} agent over the shared engagement evidence.")
    # Deferred import, matching execute_command's own use of handle_prompt.
    # The flat module referenced handle_prompt here without importing it at
    # module scope; binding it locally (as execute_command already does) keeps
    # the deferred-import style and makes the targeted-scan path resolvable.
    from cli.commands.prompt import handle_prompt
    handle_prompt(_PHASE_PROMPTS[phase].format(target=target), client)


def _poll_foreground_job(
    client: "APIClient",
    events,
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
    job_id = ""
    try:
        with console.status(f"[bold cyan]{spinner_text}[/]", spinner="dots") as spinner:
            for event in events:
                job_id = str(event.data.get("job_id") or job_id)
                if event.type == "job_started":
                    print_info(f"{label} started (job {job_id}).")
                elif event.type == "job_log":
                    line = event.data.get("line", "")
                    console.print(f"  [green]{line}[/]")
                elif event.type == "job_progress":
                    progress = str(event.data.get("progress") or "")
                    spinner.update(f"[bold cyan]{progress}[/]")
                elif event.type == "job_cancelled":
                    print_error(
                        f"Interrupted — {label.lower()} job cancelled. Findings gathered so far are saved."
                    )
                    return None
                elif event.type == "error":
                    print_error(f"{label} failed: {event.data.get('message', 'unknown error')}")
                    return None
                elif event.type == "job_completed":
                    return event.data
    except Exception as exc:
        print_error(_api_error_text(exc))
        if job_id:
            print_info(
                f"Lost contact while {label.lower()} job {job_id} was running; "
                "the server-side job may still be active. Reconnect and check its status."
            )
    return None



def handle_fast_scan(args: list[str], client: "APIClient") -> None:
    """Deterministic, no-LLM, no-sister-domain fast scan.

    Usage: /fast-scan <domain> [--engine]

    whois -> direct subdomain enumeration (no domain_hunter/sister discovery)
    -> TLS cert SAN pass (merges in-scope SANs) -> resolve every host to IPs
    + CNAMEs -> classify CDN-edge vs origin IPs -> httpx live-probe -> nmap
    deep scan (service + OS detection, tuned min-rate, top ports) on origin
    IPs, a light 80/443 check on CDN-fronted IPs -> dangling-CNAME takeover
    check. Narrower and faster than /scan (the full investigation loop) —
    still passive/direct against the target's own DNS/TLS/IP
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


def handle_jobs(args: list[str], client: "APIClient") -> None:
    """List durable jobs for the active engagement: /jobs [status]."""
    from cli.harness import get_runtime

    runtime = get_runtime(client)
    if not runtime.active_engagement_id:
        print_error("No engagement bound.")
        return
    status = args[0].lower() if args else ""
    try:
        jobs = runtime.list_jobs(status=status)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return
    if not jobs:
        print_info("No jobs for this engagement" + (f" with status={status}." if status else "."))
        return
    for job in jobs:
        job_id = str(job.get("job_id") or "?")
        kind = str(job.get("kind") or "job")
        state = str(job.get("status") or "unknown")
        progress = str(job.get("progress") or "").strip()
        print_info(f"{job_id}  {kind}  {state}" + (f" — {progress}" if progress else ""))


def handle_job(args: list[str], client: "APIClient") -> None:
    """Show one job's current state: /job <job_id>."""
    if not args:
        print_info("Usage: /job <job_id>")
        return
    from cli.harness import get_runtime

    try:
        job = get_runtime(client).get_job(args[0])
    except Exception as exc:
        print_error(_api_error_text(exc))
        return
    print_info(
        f"{job.get('job_id', args[0])}  {job.get('kind', 'job')}  "
        f"{job.get('status', 'unknown')} — {job.get('progress', '')}"
    )
    for line in (job.get("results_log") or [])[-10:]:
        console.print(f"  [green]{line}[/]")
    if job.get("error"):
        print_error(str(job["error"]))


def handle_cancel(args: list[str], client: "APIClient") -> None:
    """Cancel one job while preserving evidence gathered so far."""
    from cli.harness import get_runtime

    runtime = get_runtime(client)
    try:
        if args:
            job = runtime.cancel_job(args[0])
        else:
            job = runtime.cancel_investigation()
    except Exception as exc:
        print_error(_api_error_text(exc))
        return
    if job:
        print_success(
            f"Cancelled job {job.get('job_id', args[0] if args else '')}. "
            "Partial evidence remains saved."
        )
    else:
        print_info("Investigation cancelled; there was no active capability job to stop.")


def handle_pause(args: list[str], client: "APIClient") -> None:
    from cli.harness import get_runtime

    if get_runtime(client).pause_investigation():
        print_success("Investigation paused. Active capability work is not cancelled.")
    else:
        print_info("No running investigation to pause.")


def handle_resume(args: list[str], client: "APIClient") -> None:
    from cli.harness import get_runtime

    runtime = get_runtime(client)
    try:
        events = runtime.resume_investigation()
    except Exception as exc:
        print_error(str(exc))
        return
    source = "supervised" if runtime.session.investigation.driver == "supervised" else "engine"
    _run_investigation_events(client, events, transcript=runtime.transcript, source=source)


def _run_fast_scan(client: "APIClient", target: str) -> bool:
    from cli.harness import get_runtime

    runtime = get_runtime(client)
    engagement_id = runtime.active_engagement_id
    if not engagement_id:
        print_error("No engagement bound.")
        return False
    status = client.execution_status()
    if not status.get("ready", True):
        print_error(status.get("message", "Tool execution backend is not ready."))
        return False
    if status.get("message"):
        print_info(status["message"])

    print_info(f"Fast scan starting on {target}.")
    print_info("whois -> subdomains -> TLS SANs -> resolve IPs/CNAMEs -> classify CDN vs origin -> "
               "httpx live-probe -> nmap (full on origin, light on CDN edges) -> takeover check.")

    polled = _poll_foreground_job(
        client,
        runtime.run_fast_scan(target),
        label="Fast scan",
        spinner_text="Fast scan starting…",
    )
    if polled is None:
        return False
    report = ((polled.get("result") or {}).get("result") or {})
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
