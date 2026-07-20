"""
Execute sister-domain discovery for affiliated root domains.

Args:
    domain: Seed root domain
    modules: Comma-separated subset of discovery modules
    confidence_min: Minimum confidence tier to report
    additional_args: Additional CLI arguments

Returns:
    Structured sister-domain discovery results
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.result import ToolResult
from _core.runner import run_tool

from domain_hunter_impl import parse_stdout

TOOL_NAME = "domain_hunter"
CATEGORY = "recon"


def build_command(**params: Any) -> str:
    """Build CLI command for local MCP execution."""
    domain = str(params.get("domain", "")).strip()
    if not domain:
        raise ValueError("domain_hunter requires a 'domain'")

    modules = str(params.get("modules", "") or "").strip()
    confidence_min = str(params.get("confidence_min", "low") or "low").strip().lower()
    output = str(params.get("output", "") or "").strip()
    additional_args = str(params.get("additional_args", "") or "").strip()

    base_dir = Path(__file__).resolve().parent / "domain-hunter"
    if not output:
        safe = domain.replace("/", "_").replace(" ", "_")
        output = f"/tmp/domain_hunter_{safe}.csv"

    parts = ["python3", "main.py", "--domain", domain, "--confidence-min", confidence_min, "--output", output]
    if modules:
        parts.extend(["--modules", modules])
    if additional_args:
        parts.append(additional_args)

    return f"cd {shlex.quote(str(base_dir))} && {' '.join(shlex.quote(part) for part in parts)}"


def parse(result: ToolResult) -> dict[str, Any]:
    rows = parse_stdout(result.raw_stdout)
    return {"rows": rows, "count": len(rows)}


def run(
    domain: str = "",
    modules: str = "",
    confidence_min: str = "low",
    output: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "domain": domain,
        "modules": modules,
        "confidence_min": confidence_min,
        "output": output,
        "additional_args": additional_args,
    }
    command = build_command(**params)
    return run_tool(
        TOOL_NAME,
        command,
        params=params,
        timeout=exec_timeout,
        use_cache=use_cache,
        use_recovery=use_recovery,
        parse_fn=parse,
    )
