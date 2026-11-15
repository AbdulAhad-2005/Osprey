"""The interactive prompt previously passed complete_while_typing=True
unconditionally to every session.prompt() call, not just "/" commands.
prompt_toolkit reserves reserve_space_for_menu's full height (12 rows) as a
MINIMUM for the input buffer whenever complete_while_typing() is true — it
checks that flag, not whether a completion menu is actually showing. On a
terminal pane shorter than ~14 rows, that unconditional 12-row minimum pushed
the real input line off-screen above the fixed bottom_toolbar: the user's
cursor and the visible "end" of the terminal (where the toolbar sits) were no
longer the same place. CommandCompleter only ever matches "/"-prefixed text,
so completion should only be live (and only then reserve the grid height)
while a slash command is actually being typed.
"""

from __future__ import annotations

import asyncio

import pytest
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.filters import Condition
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.shortcuts import CompleteStyle

from cli.main import PromptSession as _MainPromptSession  # noqa: F401 (import-safety check)


class _StubCompleter(Completer):
    """Same shape as cli.main.CommandCompleter — only matches "/"-prefixed text."""

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if text.startswith("/"):
            yield Completion("/help", start_position=-len(text))


def _make_condition(session):
    """Exactly the Condition cli.main._prompt_loop_body passes to session.prompt."""
    return Condition(lambda: session.default_buffer.text.startswith("/"))


async def _reserved_heights():
    with create_pipe_input() as inp:
        session = _MainPromptSession(
            completer=_StubCompleter(),
            complete_style=CompleteStyle.MULTI_COLUMN,
            reserve_space_for_menu=12,
            input=inp,
            output=DummyOutput(),
        )
        app_task = asyncio.ensure_future(session.app.run_async())
        await asyncio.sleep(0.05)  # let the app establish a running context

        session.complete_while_typing = _make_condition(session)

        session.default_buffer.text = "scan example.com for open ports"
        plain_height = session._get_default_buffer_control_height()

        session.default_buffer.text = "/help"
        slash_height = session._get_default_buffer_control_height()

        session.app.exit()
        try:
            await asyncio.wait_for(app_task, timeout=1)
        except Exception:
            pass
        return plain_height, slash_height


def test_plain_text_reserves_no_minimum_height():
    """Ordinary prompt text (no leading "/") must not reserve the completion
    grid's height — this is what kept the input line on-screen."""
    plain_height, _ = asyncio.run(_reserved_heights())
    assert plain_height.min == 0


def test_slash_command_still_reserves_the_full_menu_grid():
    """A "/" command must still get the intentional 12-row reservation so all
    44 slash commands remain visible at once — this fix must not regress that
    UX feature, only stop it firing for non-slash text."""
    _, slash_height = asyncio.run(_reserved_heights())
    assert slash_height.min == 12


def test_prompt_loop_passes_a_condition_not_a_blanket_bool():
    """Guard against silently reverting to complete_while_typing=True: read
    the actual source so a future edit that removes the Condition fails here
    instead of only showing up as a hard-to-diagnose rendering bug."""
    import inspect

    from cli.main import _prompt_loop_body

    src = inspect.getsource(_prompt_loop_body)
    assert "complete_while_typing=True" not in src
    assert "Condition(" in src
