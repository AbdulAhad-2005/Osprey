"""
Metagoofil — discover public documents (pdf/doc/xls/ppt…) indexed for a domain.
Pair with `exiftool_extract` (forensics) to pull author names, software and GPS
from any downloaded file. Keyless.

Args:
    domain: Target domain to search for public documents
    target: Alias for domain
    file_types: Comma-separated extensions (default pdf,doc,docx,xls,xlsx,ppt,pptx)
    limit: Max documents to enumerate (default 50)
    additional_args: Extra metagoofil flags (any)

Category: osint

Passive discovery: enumerates document URLs from public search indexes. Metadata
extraction (names/software) is a follow-up via exiftool_extract on the files.
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

TOOL_NAME = "metagoofil"
CATEGORY = "osint"

_DEFAULT_TYPES = "pdf,doc,docx,xls,xlsx,ppt,pptx"


def build_command(**params: Any) -> str:
    domain = str(params.get("domain") or params.get("target") or "").strip()
    file_types = str(params.get("file_types") or _DEFAULT_TYPES).strip()
    limit = str(params.get("limit") or 50).strip()
    additional_args = str(params.get("additional_args") or "").strip()

    if not domain:
        raise ValueError("metagoofil requires domain= (or target=)")

    out_dir = f"/tmp/metagoofil_{domain.replace('/', '_')}"
    parts = [
        "metagoofil",
        "-d", shlex.quote(domain),
        "-t", shlex.quote(file_types),
        "-l", shlex.quote(limit),
        "-o", shlex.quote(out_dir),
    ]
    if additional_args:
        parts.append(additional_args)
    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    text = result.raw_stdout or ""
    docs = [ln for ln in text.splitlines() if "http" in ln]
    return {"documents": len(docs)}


def run(
    domain: str = "",
    target: str = "",
    file_types: str = "",
    limit: int = 50,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "domain": domain,
        "target": target,
        "file_types": file_types,
        "limit": limit,
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
