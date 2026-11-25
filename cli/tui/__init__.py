"""Textual TUI shell for Osprey (prototype).

An opt-in full-screen operator shell (`osprey tui`) that runs alongside the
existing prompt_toolkit REPL. It exists to prove the UX the blocking REPL
can't give: a persistent input box you can type into *while a turn is
running*, a live phase/activity sidepane, and a context-token HUD — the
Claude-Code / opencode shape — while reusing the exact same ``HarnessRuntime``
and ``APIClient`` the REPL drives, untouched.
"""

from __future__ import annotations


def textual_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("textual") is not None


def run_tui(target: str | None = None) -> int:
    """Launch the integrated full-screen shell. Imported lazily so the rest of
    the CLI never pays the Textual import cost, and a missing Textual install
    degrades to a clear message instead of a traceback."""
    try:
        from cli.tui.app import OspreyShell
    except ModuleNotFoundError as exc:  # pragma: no cover - install hint path
        if exc.name == "textual":
            print(
                "The shell needs Textual, which isn't installed.\n"
                "  pip install 'textual>=0.80,<2.0'   (or: pip install -e \"./cli[tui]\")\n"
                "Falling back to the classic line REPL — run `osprey --classic`."
            )
            return 1
        raise
    return OspreyShell(initial_target=target).run() or 0
