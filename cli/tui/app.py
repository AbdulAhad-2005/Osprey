"""Osprey integrated shell (Textual).

This is the CLI's interactive mode rendered full-screen — not a second UI. The
whole existing command stack (``execute_command``, ``handle_prompt`` and the
``cli.ui.display`` renderers) writes through one shared ``rich`` Console, which
``console_redirect`` points at the activity log — so every command renders live
here with zero per-command code. The shell only adds what a blocking readline
loop can't: an always-live input (type while a job runs; it queues), inline
``/`` completion, command history, interrupts that don't wait in line, and a
sidepane. The harness (``HarnessRuntime``/``APIClient``) is reused untouched.

Threading: Textual owns the screen on the main thread; one worker thread runs
blocking commands off a queue, and interrupts (/cancel) run on their own thread
so they don't wait behind the job they're meant to stop. Everything marshals
back to the UI with ``call_from_thread``.
"""

from __future__ import annotations

import builtins
import queue
import threading
from pathlib import Path
from typing import Any

from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Footer, Header, Input, OptionList, RichLog, Static
from textual.widgets.option_list import Option

from agent_core.net import resolve_api_base_url
from cli.api.client import APIClient
from cli.commands.slash import SLASH_COMMANDS, execute_command
from cli.harness import get_runtime
from cli.tui import console_redirect
from cli.tui.widgets import PromptModal, Sidebar

_INTERRUPTS = {"/cancel", "/pause", "/stop"}

_WELCOME = """[b cyan]Osprey[/]  ·  integrated operator shell

Type a prompt to drive the agent, or a [b]/command[/] ([b]Tab[/] to complete, [b]↑[/] for history).
The input stays live while a job runs — new lines queue and send when it finishes.
Every CLI command works here: [cyan]/scan /engage /findings /status /context /report[/] …
[dim]/help lists them all · Ctrl+C quit · Ctrl+L clear[/]"""


class OspreyShell(App[int]):
    CSS_PATH = "app.tcss"
    BINDINGS = [
        ("ctrl+c", "quit", "Quit"),
        ("ctrl+l", "clear_log", "Clear"),
    ]

    def __init__(self, *, initial_target: str | None = None) -> None:
        super().__init__()
        self._initial_target = initial_target
        self._runtime: Any = None
        self._jobs: "queue.Queue[str]" = queue.Queue()
        self._answer: "queue.Queue[str]" = queue.Queue()
        self._stop = threading.Event()
        self._busy = False
        self._busy_since = 0.0
        self._activity = ""
        self._history: list[str] = []
        self._hist_idx = 0

    # ---- layout ---------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            yield RichLog(id="log", wrap=True, markup=True, highlight=True, auto_scroll=True)
            yield Sidebar(id="side")
        yield Static("", id="statusline")
        yield OptionList(id="completions")
        yield Input(placeholder="prompt or /command   (Tab completes · ↑ history · /help)", id="prompt")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Osprey"
        self.sub_title = "operator shell"
        self.query_one("#log", RichLog).write(Text.from_markup(_WELCOME))
        self.query_one("#prompt", Input).focus()
        self._refresh_statusline()
        self.set_interval(1.0, self._tick)  # live elapsed timer while busy
        threading.Thread(target=self._setup, name="osprey-setup", daemon=True).start()

    def _tick(self) -> None:
        if self._busy:
            self._refresh_statusline()

    # ---- connection + worker lifecycle ---------------------------------
    def _setup(self) -> None:
        try:
            client = APIClient(base_url=resolve_api_base_url())
            self._runtime = get_runtime(client)
            width = self.query_one("#log", RichLog).size.width - 2
            console_redirect.install(self, width)
            try:
                reachable = client.health().get("status") == "ok"
            except Exception:
                reachable = False
            self.call_from_thread(self._after_connect, client.base_url, reachable)
        except Exception as exc:  # pragma: no cover
            self.call_from_thread(self._log_error, f"Setup failed: {exc}")
            return
        try:
            self._runtime.start_event_stream(
                lambda src, et, data: self.call_from_thread(self._render_background, src, et, data)
            )
        except Exception:
            pass
        threading.Thread(target=self._worker, name="osprey-worker", daemon=True).start()
        threading.Thread(target=self._poller, name="osprey-poller", daemon=True).start()
        if self._initial_target:
            self._jobs.put(f"/scan {self._initial_target}")

    def _after_connect(self, base_url: str, reachable: bool) -> None:
        from agent_core.llm import clean_env_value

        model = clean_env_value("LLM_MODEL") or "NOT CONFIGURED"
        self.query_one(Sidebar).set_model(Text(model, style="green" if "NOT" not in model else "red"))
        self.sub_title = f"{model}  ·  {'connected' if reachable else 'offline'}"
        log = self.query_one("#log", RichLog)
        log.write(f"[green]● connected[/]  {base_url}" if reachable
                  else f"[red]● backend unreachable[/]  {base_url} — run [b]docker compose up -d[/]")
        self._refresh_tokens()

    def _worker(self) -> None:
        builtins.input = self._tui_input  # handlers' input() -> modal
        while not self._stop.is_set():
            try:
                text = self._jobs.get(timeout=0.25)
            except queue.Empty:
                continue
            self.call_from_thread(self._set_busy, True)
            try:
                self._run(text)
            except Exception as exc:  # noqa: BLE001
                self.call_from_thread(self._log_error, f"Command failed: {exc}")
            finally:
                self.call_from_thread(self._set_busy, False)
                self.call_from_thread(self._refresh_tokens)
                self.call_from_thread(self._update_queue_depth)

    def _run(self, text: str) -> None:
        self.call_from_thread(self.write_line, Text(f"❯ {text}", style="bold cyan"))
        if text.startswith("/"):
            cmd = text.split()[0].lower()
            if cmd in {"/exit", "/quit", "/q"}:
                self._stop.set()
                self.call_from_thread(self.exit, 0)
                return
            if cmd == "/clear":
                self.call_from_thread(self.query_one("#log", RichLog).clear)
                return
            execute_command(text, self._runtime)
        else:
            from cli.commands.prompt import handle_prompt

            handle_prompt(text, self._runtime)

    def _run_interrupt(self, text: str) -> None:
        try:
            execute_command(text, self._runtime)
        except Exception as exc:  # noqa: BLE001
            self.call_from_thread(self._log_error, f"{text} failed: {exc}")

    def _poller(self) -> None:
        last_eng = None
        while not self._stop.is_set():
            rt = self._runtime
            if rt is not None:
                eid = rt.active_engagement_id
                if eid and eid != last_eng:
                    last_eng = eid
                    self.call_from_thread(self._set_engagement, eid, rt.active_target or "")
                if eid:
                    try:
                        self.call_from_thread(self._render_phases, rt.get_pipeline_activity(eid))
                    except Exception:
                        pass
                    try:
                        self.call_from_thread(self._render_findings, rt.list_findings_grouped(eid))
                    except Exception:
                        pass
                try:
                    count = len(rt.transcript.recent(100000))
                    self.call_from_thread(
                        self.query_one(Sidebar).set_session, Text(f"{count} tool call(s)", style="cyan")
                    )
                except Exception:
                    pass
            self.call_from_thread(self._refresh_tokens)
            self._stop.wait(4)

    def _render_findings(self, data: dict) -> None:
        total = data.get("total_findings", 0) or 0
        if not total:
            self.query_one(Sidebar).set_findings(Text.from_markup("[dim]none yet[/]"))
            return
        tally: dict[str, int] = {}
        for g in data.get("groups") or []:
            sev = str(g.get("severity") or "info").lower()
            tally[sev] = tally.get(sev, 0) + int(g.get("count", 0) or 0)
        order = [("critical", "crit", "bold red"), ("high", "high", "red"),
                 ("medium", "med", "yellow"), ("low", "low", "blue")]
        parts = [f"[{color}]{tally[k]} {lbl}[/]" for k, lbl, color in order if tally.get(k)]
        line = "  ".join(parts) if parts else "[dim]info-only[/]"
        self.query_one(Sidebar).set_findings(Text.from_markup(f"{line}\n[dim]{total} total[/]"))

    # ---- input() modal bridge ------------------------------------------
    def _tui_input(self, prompt: str = "") -> str:
        if "dashboard" in str(prompt).lower():
            return "n"  # the shell has its own live view; skip the per-bind offer
        self.call_from_thread(lambda: self.push_screen(PromptModal(str(prompt)), lambda a: self._answer.put(a or "")))
        try:
            return self._answer.get(timeout=300)
        except queue.Empty:
            return ""

    # ---- rendering (UI thread) -----------------------------------------
    def write_line(self, renderable) -> None:
        self.query_one("#log", RichLog).write(renderable)

    def _render_background(self, source: str, etype: str, data: dict) -> None:
        if not source or source == "tool":
            return
        if etype == "assistant":
            content = (data.get("content") or "").strip()
            if content:
                self.write_line(Text(f"[{source}] {content[:200]}", style="yellow"))
        elif etype in ("tool_start", "tool_end"):
            self.write_line(Text(f"[{source}] {data.get('tool_name','?')}", style="yellow"))

    def _render_phases(self, activity: dict) -> None:
        pr = activity.get("phase_readiness") or {}
        phases = pr.get("phases") or {}
        sig = pr.get("signals") or {}
        recon = phases.get("recon") or {}
        rows = [("recon", "[green]● active[/]" if recon.get("always_active") else "[dim]idle[/]")]
        for name in ("vuln", "exploit"):
            rows.append((name, "[green]✓ unlocked[/]" if (phases.get(name) or {}).get("unlocked") else "[dim]🔒 locked[/]"))
        body = "\n".join(f"{n:<9}{s}" for n, s in rows)
        counts = (f"[dim]subs {sig.get('subdomains',0)}  hosts {sig.get('live_hosts',0)}  "
                  f"svcs {sig.get('services',0)}  tech {sig.get('technologies',0)}\n"
                  f"urls {sig.get('urls',0)}  vulns {sig.get('vulnerabilities',0)}  "
                  f"creds {sig.get('credentials',0)}[/]")
        self.query_one(Sidebar).set_phases(Text.from_markup(f"{body}\n{counts}"))

    def _refresh_tokens(self) -> None:
        if self._runtime is None:
            return
        try:
            from agent_core.compaction import count_message_tokens, resolve_context_limit
            from agent_core.llm import clean_env_value

            model = clean_env_value("LLM_MODEL") or ""
            if not model:
                return
            messages = self._runtime.conversation_messages()
            tokens = count_message_tokens(model, messages) if messages else 0
            limit = resolve_context_limit(model) or 1
            pct = min(100, int(tokens * 100 / limit))
            bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
            style = "green" if pct < 60 else ("yellow" if pct < 85 else "red")
            self.query_one(Sidebar).set_tokens(Text(f"{tokens:,} / {limit:,}\n[{bar}] {pct}%", style=style))
        except Exception:
            pass

    def _set_engagement(self, eid: str, target: str) -> None:
        self.query_one(Sidebar).set_engagement(Text(f"{eid}\n{target}", style="green"))

    def _log_error(self, message: str) -> None:
        self.write_line(Text(f"Error: {message}", style="bold red"))

    # ---- status line ----------------------------------------------------
    def set_activity(self, text: str) -> None:
        self._activity = text
        self._refresh_statusline()

    def _set_busy(self, busy: bool) -> None:
        import time

        if busy and not self._busy:
            self._busy_since = time.monotonic()
        self._busy = busy
        if not busy:
            self._activity = ""
        self._refresh_statusline()

    def _update_queue_depth(self) -> None:
        self._refresh_statusline()

    def _refresh_statusline(self) -> None:
        import time

        depth = self._jobs.qsize()
        if self._busy:
            elapsed = int(time.monotonic() - self._busy_since) if self._busy_since else 0
            parts = [f"[yellow]● running {elapsed}s[/]"]
            if self._activity:
                parts.append(f"[dim]{self._activity[:56]}[/]")
            parts.append("[dim]Esc to stop[/]")
        else:
            parts = ["[dim]○ idle[/]"]
        if depth:
            parts.append(f"[cyan]{depth} queued[/]")
        self.query_one("#statusline", Static).update(Text.from_markup("  ·  ".join(parts)))

    # ---- input, completion, history ------------------------------------
    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "prompt":
            return
        self._hide_completions()
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return
        self._history.append(text)
        self._hist_idx = len(self._history)
        if self._runtime is None:
            self.write_line(Text("connecting… try again in a moment", style="dim"))
            return
        if text.split()[0].lower() in _INTERRUPTS:
            self.write_line(Text(f"❯ {text}", style="bold cyan"))
            threading.Thread(target=self._run_interrupt, args=(text,), daemon=True).start()
            return
        self._jobs.put(text)
        if self._busy:
            self.write_line(Text(f"queued: {text}", style="dim"))
        self._update_queue_depth()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "prompt":
            return
        value = event.value
        comp = self.query_one("#completions", OptionList)
        if value.startswith("/") and " " not in value:
            matches = [(c, d) for c, (d, _) in sorted(SLASH_COMMANDS.items()) if c.startswith(value.lower())]
            if matches:
                comp.clear_options()
                for cmd, desc in matches[:40]:
                    comp.add_option(Option(f"[b cyan]{cmd}[/]  [dim]{desc}[/]", id=cmd))
                comp.highlighted = 0
                comp.add_class("show")
                return
        self._hide_completions()

    def _hide_completions(self) -> None:
        comp = self.query_one("#completions", OptionList)
        comp.remove_class("show")
        comp.clear_options()

    def _accept_completion(self) -> None:
        comp = self.query_one("#completions", OptionList)
        if not comp.option_count:
            return
        idx = comp.highlighted or 0
        cmd = comp.get_option_at_index(idx).id or ""
        inp = self.query_one("#prompt", Input)
        inp.value = cmd + " "
        inp.cursor_position = len(inp.value)
        self._hide_completions()

    def on_key(self, event: events.Key) -> None:
        comp = self.query_one("#completions", OptionList)
        showing = comp.has_class("show")
        if showing and event.key in ("tab", "down", "up", "escape", "enter"):
            if event.key == "tab":
                self._accept_completion()
            elif event.key == "enter":
                self._accept_completion()
            elif event.key == "down":
                comp.highlighted = min((comp.highlighted or 0) + 1, comp.option_count - 1)
            elif event.key == "up":
                comp.highlighted = max((comp.highlighted or 0) - 1, 0)
            elif event.key == "escape":
                self._hide_completions()
            event.prevent_default()
            event.stop()
            return
        # Esc stops the running job (the standard "get me out" key) when the
        # completion menu isn't up.
        if event.key == "escape" and self._busy and self._runtime is not None:
            self.write_line(Text("❯ /cancel", style="bold cyan"))
            threading.Thread(target=self._run_interrupt, args=("/cancel",), daemon=True).start()
            event.prevent_default()
            event.stop()
            return
        # history recall when the completion menu isn't up
        if event.key in ("up", "down") and self._history:
            if event.key == "up":
                self._hist_idx = max(0, self._hist_idx - 1)
            else:
                self._hist_idx = min(len(self._history), self._hist_idx + 1)
            inp = self.query_one("#prompt", Input)
            inp.value = self._history[self._hist_idx] if self._hist_idx < len(self._history) else ""
            inp.cursor_position = len(inp.value)
            event.prevent_default()
            event.stop()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self._accept_completion()
        self.query_one("#prompt", Input).focus()

    def on_resize(self, event: events.Resize) -> None:
        try:
            from cli.ui import display

            display.console._width = max(40, self.query_one("#log", RichLog).size.width - 2)
        except Exception:
            pass

    # ---- actions --------------------------------------------------------
    def action_clear_log(self) -> None:
        self.query_one("#log", RichLog).clear()

    def action_quit(self) -> None:  # type: ignore[override]
        self._stop.set()
        if self._runtime is not None:
            try:
                self._runtime.close()
            except Exception:
                pass
        self.exit(0)


# Belt-and-braces: guarantee the stylesheet resolves next to this module even
# if the CWD differs when launched.
OspreyShell.CSS_PATH = str(Path(__file__).with_name("app.tcss"))
