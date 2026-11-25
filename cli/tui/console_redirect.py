"""Bridge the CLI's shared ``rich`` Console into the Textual log.

Every CLI command — the slash handlers and the agent loop — renders through
one shared ``cli.ui.display.console``. We point that Console's output at the
activity log and replace its spinner, so all ~40 commands render live in the
shell with no per-command code. Kept in its own module so ``app.py`` stays a
UI file, not a Rich-internals file.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from rich.text import Text

if TYPE_CHECKING:
    from cli.tui.app import OspreyShell


class LogWriter:
    """File-like sink: Rich writes ANSI here; we forward whole lines to the
    RichLog on the UI thread, re-parsing the ANSI into styled text. Locked
    because interrupts (/cancel) render from a second thread concurrently."""

    def __init__(self, app: "OspreyShell") -> None:
        self._app = app
        self._buf = ""
        self._lock = threading.Lock()

    def write(self, s: str) -> int:
        with self._lock:
            self._buf += s
            lines = []
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                lines.append(line)
        for line in lines:
            self._app.call_from_thread(self._app.write_line, Text.from_ansi(line))
        return len(s)

    def flush(self) -> None:
        with self._lock:
            line, self._buf = self._buf, ""
        if line:
            self._app.call_from_thread(self._app.write_line, Text.from_ansi(line))


class NoopStatus:
    """Replacement for ``console.status(...)``. The handlers drive a Rich
    spinner (a Live display) for "working…", which paints cursor-control
    escapes that are meaningless in a scrollback log. We route its text to the
    shell's status line instead and make the context manager inert."""

    def __init__(self, app: "OspreyShell", text: str = "") -> None:
        self._app = app
        self._app.call_from_thread(self._app.set_activity, _plain(text))

    def __enter__(self) -> "NoopStatus":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def update(self, text: str = "", **_: Any) -> None:
        self._app.call_from_thread(self._app.set_activity, _plain(text))

    def start(self) -> None:
        pass

    def stop(self) -> None:
        self._app.call_from_thread(self._app.set_activity, "")


def _plain(markup: Any) -> str:
    try:
        return Text.from_markup(str(markup)).plain
    except Exception:
        return str(markup)


def install(app: "OspreyShell", log_width: int) -> None:
    """Point the shared console at the shell. Called once, after connect."""
    from cli.ui import display

    display.console.file = LogWriter(app)
    display.console._force_terminal = True
    display.console._width = max(40, log_width)
    display.console.status = lambda *a, **k: NoopStatus(app, a[0] if a else "")
