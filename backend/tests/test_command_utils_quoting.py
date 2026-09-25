"""_core.command_utils.q() — the shared quoting helper applied across the
41-file wrapper sweep (see the approved plan). Loaded by path since
mcp-servers/ isn't an installed backend package."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[2] / "mcp-servers" / "_core" / "command_utils.py"


def _load():
    spec = importlib.util.spec_from_file_location("_command_utils_test", _MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cu = _load()


def test_q_empty_and_none_become_empty_string():
    assert _cu.q(None) == ""
    assert _cu.q("") == ""


def test_q_plain_value_unquoted():
    assert _cu.q("example.com") == "example.com"


def test_q_space_gets_quoted():
    assert _cu.q("eth0 *") == "'eth0 *'"


def test_q_shell_metachar_gets_quoted():
    assert _cu.q("foo; rm -rf /") == "'foo; rm -rf /'"


def test_q_embedded_single_quote_is_escaped_safely():
    value = "it's a test"
    quoted = _cu.q(value)
    # shlex.quote's own escaping contract — round-trips through shlex.split.
    import shlex
    assert shlex.split(quoted) == [value]


def test_q_non_string_coerced():
    assert _cu.q(443) == "443"
