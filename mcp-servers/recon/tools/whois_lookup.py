"""WHOIS lookup via system whois binary."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "whois_lookup"
CATEGORY = "recon"


def build_command(**params: Any) -> str:
    target = params.get("target") or params.get("domain") or ""
    additional_args = params.get("additional_args", "")
    command = f"whois {target}"
    if additional_args:
        command += f" {additional_args}"
    return command


def parse_output(raw: ToolResult) -> dict[str, Any]:
    return default_parse(raw)


if __name__ == "__main__":
    run_tool(TOOL_NAME, CATEGORY, build_command, parse_output)
