"""JS reconnaissance — endpoint + secret + cloud-asset extraction from JavaScript.

Thin build_command wrapper around ``_js_recon_cli.py`` (stdlib-only worker that
runs inside the Kali container). Discovers a page's scripts, downloads them, and
mines endpoints / hardcoded secrets / exposed cloud storage. Recon-phase: for
modern SPA/API targets the real attack surface lives in the JS bundles, not the
served HTML.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "js_recon"
CATEGORY = "recon"

# Fixed container path (mirrors the shodan/domain-hunter pattern).
from _core.paths import container_or_local

_CLI = container_or_local(
    "/home/mcpuser/mcp-servers/recon/tools/_js_recon_cli.py",
    str(Path(__file__).resolve().with_name("_js_recon_cli.py")),
)


def build_command(**params: Any) -> str:
    target = str(params.get("target") or params.get("url") or params.get("domain") or "").strip()
    if not target:
        raise ValueError("js_recon requires target= (page URL, JS URL, or list)")
    max_files = int(params.get("max_files") or 40)
    timeout = int(params.get("timeout") or 15)
    additional_args = str(params.get("additional_args") or "").strip()

    parts = [
        "python3", shlex.quote(_CLI),
        "--target", shlex.quote(target),
        "--max-files", str(max_files),
        "--timeout", str(timeout),
    ]
    cmd = " ".join(parts)
    if additional_args:
        cmd += f" {additional_args}"
    return cmd


def parse(result: ToolResult) -> dict[str, Any]:
    from _core.runner import default_parse
    return default_parse(result)


def run(
    target: str = "",
    url: str = "",
    max_files: int = 40,
    timeout: int = 15,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 180,
) -> dict[str, Any]:
    params = {
        "target": target or url,
        "max_files": max_files,
        "timeout": timeout,
        "additional_args": additional_args,
    }
    return run_tool(
        TOOL_NAME,
        build_command(**params),
        params=params,
        timeout=exec_timeout,
        use_cache=use_cache,
        use_recovery=use_recovery,
        parse_fn=parse,
    )
