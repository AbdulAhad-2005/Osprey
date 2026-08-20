"""Shared shell-quoting helper for tool wrappers building a command string.

Every wrapper here interpolates target/host/url/domain/ports-family values
into an f-string that ultimately runs via ``bash -c`` inside the Kali
container (see mcp_client.py::_call_via_docker_exec) — a real shell, not the
tokenized ``_core.executor.run_command`` path. param_validator.py blocks
classic shell metacharacters (``;|&`$()<>``) in param values before a
wrapper ever sees them, but that blocklist does not cover spaces (word-
splitting a value into extra argv tokens), quote characters, glob
characters, ``~``, or ``#`` — exactly the residual gap this closes.
"""

from __future__ import annotations

import shlex
from typing import Any


def q(value: Any) -> str:
    """Shell-quote a value for safe interpolation into an f-string command.

    ``None`` and falsy values become an empty (unquoted) string rather than
    ``''``, so an optional flag's ``if value:`` guard upstream still works
    the same way it did before this value was quoted.
    """
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    return shlex.quote(text)
