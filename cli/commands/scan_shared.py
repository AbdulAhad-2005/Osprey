"""Engagement binding + investigation-event rendering shared between
``slash.py`` (``/scan``, ``/engage``, ``/resume``) and ``prompt.py`` (the
no-LLM-configured fallback offered from a bare prompt). Split out to avoid a
circular import — ``slash.py`` already imports ``handle_prompt`` from
``prompt.py``, so anything ``prompt.py`` needs from the scan machinery has
to live somewhere neither module owns.
"""

from __future__ import annotations

import json
import time
import webbrowser
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from cli.api.client import APIClient
    from cli.session import ToolTranscript

from cli.ui.display import (
    console,
    print_error,
    print_info,
    print_success,
    print_tool_end_live,
    print_tool_start_live,
)


def _bind_engagement(client: "APIClient", data: dict) -> None:
    """Store the active engagement from an engagement payload and report it."""
    engagement_id = data.get("id") or data.get("engagement_id")
    if not engagement_id:
        print_error(f"Engagement response had no id: {data}")
        return
    from cli.harness import get_runtime

    get_runtime(client).bind_engagement(
        engagement_id, target=str(data.get("target") or "")
    )
    label = data.get("target") or engagement_id
    reused = data.get("reused", False)
    if reused:
        print_info(f"Reusing existing engagement {engagement_id} for {label}")
    else:
        print_success(f"Engagement bound: {engagement_id} for {label}")
    _offer_dashboard(client, engagement_id)


def _offer_dashboard(client: "APIClient", engagement_id: str) -> None:
    """Every tool call for this engagement already streams onto the shared
    event bus (``tool_execution.execute_tool_request`` publishes tool_start/
    tool_end for every path — MCP, the free-LLM loop, --engine/--supervised).
    The dashboard is just a browser tab on that existing stream, so offering
    it costs nothing beyond opening a URL."""
    try:
        answer = input("Open a live dashboard for this engagement in your browser? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if answer not in ("y", "yes"):
        return
    url = f"{client.base_url}/api/v1/dashboard/{engagement_id}"
    opened = False
    try:
        opened = webbrowser.open(url)
    except Exception:  # noqa: BLE001 — headless/no-display environments
        opened = False
    if opened:
        print_info(f"Dashboard opened: {url}")
    else:
        print_info(f"Dashboard: {url}")


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


def _capability_result_detail(data: dict) -> dict:
    """Dig the first per-tool result out of a capability_completed event's
    nested ``{job, result: {details: {results: [...]}}, note}`` payload
    (``result`` here is the backend's full ``JobResultResponse``, not the
    bare ``CapabilityResult`` — one extra layer of nesting). Defensive: any
    missing level just yields an empty dict, never a KeyError mid-render."""
    capability_result = (data.get("result") or {}).get("result") or {}
    results = (capability_result.get("details") or {}).get("results") or []
    return dict(results[0]) if results else {}


def _run_investigation_events(
    client: "APIClient", events, *, transcript: "ToolTranscript | None" = None, source: str = "engine",
) -> bool:
    """Render the deterministic/supervised investigation lifecycle through
    the SAME transcript-backed tool-call renderer the free-LLM ReAct loop
    and background pipeline events already use (``print_tool_start_live``/
    ``print_tool_end_live``) — one opportunity is exactly one real tool call
    (Plan 17/18), so it renders exactly like a real tool call, tagged
    ``[engine]``/``[checkpoint]`` instead of inventing a second, cruder
    rendering system for "the same thing, but from the deterministic loop."
    """
    if transcript is None:
        from cli.harness import get_runtime

        transcript = get_runtime(client).transcript

    succeeded = True
    # Multiple opportunities now run concurrently (plan 19 Part B), so track each
    # in flight by its opportunity_id: tool name + when its card was shown. A
    # completion is matched back to its start by opportunity_id, so overlapping
    # tool calls render as independent cards instead of one being mislabelled.
    inflight: dict[str, dict] = {}
    with console.status("[bold cyan]Investigation running…[/]", spinner="dots") as spinner:
        for event in events:
            data = event.data
            if event.type == "state":
                summary = str(data.get("state_summary") or "").strip()
                if summary:
                    spinner.update(f"[bold cyan]{summary}[/]")
            elif event.type == "opportunities":
                pass  # folded into the spinner via "state"; the next "decision" is what matters
            elif event.type == "decision":
                opp_id = str(data.get("opportunity_id") or "")
                tool = str(data.get("tool") or "")
                params = data.get("params") or {}
                if tool:
                    inflight[opp_id] = {"tool": tool, "started_at": time.monotonic()}
                    print_tool_start_live(
                        tool, params, {"tool_call_id": opp_id},
                        transcript=transcript, source=source,
                    )
                else:
                    # An analytical opportunity (no tool —
                    # detect_anomalies/refresh_exploit_candidates/sweep_netblock):
                    # a real action, just not a Kali tool call, so it gets a
                    # spinner update, never a fake tool-call card.
                    label = data.get("capability") or "opportunity"
                    reason = data.get("rationale") or "highest-priority opportunity"
                    spinner.update(f"[bold cyan]{label}[/] — {reason}")
            elif event.type == "capability_started":
                # For a launched opportunity the "decision" above already drew
                # the start card. A RESUMED job (adopted on /resume) has no
                # decision this session, so draw its start card here.
                if data.get("resumed") and data.get("tool"):
                    opp_id = str(data.get("opportunity_id") or data.get("job_id") or "")
                    inflight[opp_id] = {"tool": str(data["tool"]), "started_at": time.monotonic()}
                    print_tool_start_live(
                        str(data["tool"]), {}, {"tool_call_id": opp_id},
                        transcript=transcript, source=source,
                    )
            elif event.type == "capability_log":
                spinner.update(f"[bold cyan]{str(data.get('line', ''))[:120]}[/]")
            elif event.type == "capability_progress":
                spinner.update(f"[bold cyan]{data.get('progress', 'Working…')}[/]")
            elif event.type == "capability_completed":
                opp_id = str(data.get("opportunity_id") or "")
                started = inflight.pop(opp_id, None)
                detail = _capability_result_detail(data)
                if started is None:
                    # No start card for this completion — either an analytical
                    # opportunity (no tool → nothing to render) or a job adopted
                    # on /resume (we missed its start this session). Render a
                    # standalone card only when the result names a real tool.
                    if not detail.get("tool"):
                        continue
                    tool = str(detail.get("tool"))
                    elapsed = 0.0
                else:
                    tool = str(detail.get("tool") or started["tool"])
                    elapsed = time.monotonic() - started["started_at"]
                print_tool_end_live(
                    tool,
                    {
                        "success": bool(detail.get("success", True)),
                        "timed_out": bool(detail.get("timed_out", False)),
                        "partial": bool(detail.get("partial", False)),
                        "duration_seconds": elapsed,
                        "finding_titles": detail.get("finding_titles") or [],
                        "preview": detail.get("error") or "",
                    },
                    transcript=transcript, source=source,
                )
            elif event.type == "checkpoint_started":
                print_info(f"— checkpoint: {data.get('reason', '')} — handing control to the LLM briefly —")
            elif event.type == "checkpoint_llm_event":
                _render_checkpoint_llm_event(data, transcript)
            elif event.type == "checkpoint_completed":
                if data.get("error"):
                    print_error(f"Checkpoint failed non-fatally ({data['error']}); deterministic engine resumes.")
                else:
                    print_info("— checkpoint done, deterministic engine resuming —")
            elif event.type == "state_stale":
                print_info(str(data.get("message") or "Evidence changed; replanning."))
            elif event.type == "paused":
                print_info(
                    "Investigation paused; the active capability job was left running. "
                    "Use /resume to reattach and continue, or /cancel to stop it."
                )
                return False
            elif event.type == "cancelled":
                print_info("Investigation cancelled. Evidence gathered so far remains saved.")
                return False
            elif event.type in {"waiting", "blocked"}:
                print_info(
                    str(data.get("state_summary") or "No executable opportunity is available yet.")
                )
                return event.type == "waiting"
            elif event.type == "error":
                print_error(str(data.get("message") or "Investigation step failed."))
                return False
            elif event.type == "complete":
                summary = data.get("state_summary")
                print_success("Investigation complete.")
                if isinstance(summary, str) and summary.strip():
                    print_info(summary.strip())
                return True
    return succeeded


def _render_checkpoint_llm_event(data: dict, transcript: "ToolTranscript") -> None:
    """A checkpoint hands the LLM the same unrestricted ReAct loop used
    everywhere else (SupervisedDeterministicDriver's own design) — its raw
    ``tool_start``/``tool_end``/``done`` events render through the identical
    tool-call renderer, tagged ``[checkpoint]``, so a checkpoint's tool calls
    look exactly like any other tool call, not a second bespoke format."""
    inner_type = str(data.get("type") or "")
    inner_data = data.get("data") or {}
    if inner_type == "tool_start":
        tool_name = str(inner_data.get("tool_name") or "?")
        try:
            arguments = json.loads(inner_data.get("arguments") or "{}")
        except (json.JSONDecodeError, ValueError):
            arguments = {}
        print_tool_start_live(
            tool_name, arguments, {"tool_call_id": inner_data.get("tool_call_id", "")},
            transcript=transcript, source="checkpoint",
        )
    elif inner_type == "tool_end":
        from cli.agent.loop import tool_result_failed

        tool_name = str(inner_data.get("tool_name") or "?")
        result = str(inner_data.get("result") or "")
        print_tool_end_live(
            tool_name,
            {
                "success": not (tool_result_failed(result) or result.startswith("BLOCKED (")),
                "duration_seconds": float(inner_data.get("duration_seconds") or 0),
                "preview": result,
                "tool_call_id": inner_data.get("tool_call_id", ""),
            },
            transcript=transcript, source="checkpoint",
        )
    elif inner_type == "done":
        content = str(inner_data.get("content") or "").strip()
        if content and not content.startswith("(stopped:"):
            console.print(f"  [dim italic][checkpoint][/] {content[:400]}")


def _run_engine_scan(client: "APIClient", target: str, *, supervised: bool = False) -> bool:
    """Drive the deterministic, no-LLM opportunity engine (``/scan --engine``)
    -- the baseline that works with no API key configured. Every opportunity
    it executes is exactly one real tool call; see
    backend/src/osprey/services/investigation_capabilities.py.

    ``supervised=True`` (``/scan --supervised``) wraps the same engine with
    bounded LLM checkpoints — see SupervisedDeterministicDriver."""
    from cli.harness import get_runtime

    runtime = get_runtime(client)
    engagement_id = runtime.active_engagement_id
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
    if supervised:
        print_info(f"Deterministic investigation starting on {target}, with LLM checkpoints.")
        return _run_investigation_events(
            client, runtime.start_supervised_investigation(),
            transcript=runtime.transcript, source="supervised",
        )
    print_info(f"Deterministic investigation starting on {target}.")
    return _run_investigation_events(
        client, runtime.start_investigation(),
        transcript=runtime.transcript, source="engine",
    )
