"""App reconnaissance — static attack-surface extraction from mobile/desktop apps.

Thin build_command wrapper around ``_app_recon_cli.py`` (stdlib-only worker that
runs inside the Kali container). Given an Android APK, iOS IPA, Electron
``.asar`` bundle, Java ``.jar``, or native binary, it mines endpoints, backend
hostnames, hardcoded secrets, exposed cloud storage, and platform metadata
(Android permissions/components, iOS URL schemes + ATS posture, cleartext
config). Recon-phase: a shipped app is a map of the backend it talks to — API
hosts and routes that subdomain/port enumeration alone never reaches.

The worker is standard-library only (zipfile/plistlib + a tiny asar reader) so
it always runs with no extra deps, exactly like js_recon; apktool/aapt are used
opportunistically for richer Android facts when present but are never required.
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

TOOL_NAME = "app_recon"
CATEGORY = "recon"

# Resolved in the shell inside the Kali container (where the filesystem is real
# and the worker + its _recon_extract sibling are mounted); the command is
# built in the backend but executed via docker exec.
_CLI_CONTAINER = "/home/mcpuser/mcp-servers/recon/tools/_app_recon_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_app_recon_cli.py"))


def _cli_expr() -> str:
    return (
        f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} "
        f"|| echo {_CLI_FALLBACK} )"
    )


def build_command(**params: Any) -> str:
    app_path = str(params.get("app_path") or params.get("file_path") or params.get("path") or "").strip()
    url = str(params.get("url") or params.get("target") or "").strip()
    if not app_path and not url:
        raise ValueError(
            "app_recon requires app_path= (a file already in the container) or "
            "url= (an app to download first)"
        )
    app_type = str(params.get("type") or params.get("app_type") or "auto").strip() or "auto"
    timeout = int(params.get("timeout") or 120)
    additional_args = str(params.get("additional_args") or "").strip()

    parts = ["python3", _cli_expr(), "--type", shlex.quote(app_type), "--timeout", str(timeout)]
    if app_path:
        parts += ["--app-path", shlex.quote(app_path)]
    if url:
        parts += ["--url", shlex.quote(url)]
    cmd = " ".join(parts)
    if additional_args:
        cmd += f" {additional_args}"
    return cmd


def parse(result: ToolResult) -> dict[str, Any]:
    from _core.runner import default_parse
    return default_parse(result)


def run(
    app_path: str = "",
    url: str = "",
    type: str = "auto",
    timeout: int = 120,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "app_path": app_path,
        "url": url,
        "type": type,
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
