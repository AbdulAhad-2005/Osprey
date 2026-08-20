"""WHOIS lookup via system whois binary.

Automatically strips subdomains to the registrable domain (e.g.
``sub.example.com`` -> ``example.com``) so the LLM does not need
to know this quirk of the ``whois`` binary.  A clear error is returned
when the input is not a valid domain.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult
from _core.domains import registrable_apex
from _core.command_utils import q

TOOL_NAME = "whois_lookup"
CATEGORY = "recon"

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def build_command(**params: Any) -> str:
    raw = params.get("target") or params.get("domain") or ""
    additional_args = params.get("additional_args", "")

    # PSL-backed apex extraction (sub.example.co.uk -> example.co.uk) so the LLM
    # need not know the whois binary wants the registrable domain.
    target = registrable_apex(raw)
    if not target or not _DOMAIN_RE.match(target):
        raise ValueError(
            f"whois_lookup requires a valid domain or IP. Got: {raw!r}. "
            "Pass a root domain (e.g. example.com) or an IP address."
        )

    command = f"whois {q(target)}"
    if additional_args:
        command += f" {additional_args}"
    return command


def parse_output(raw: ToolResult) -> dict[str, Any]:
    return default_parse(raw)


if __name__ == "__main__":
    run_tool(TOOL_NAME, CATEGORY, build_command, parse_output)
