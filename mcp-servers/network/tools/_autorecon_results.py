"""Directory-based result collection for AutoRecon.

AutoRecon streams progress/heartbeat noise to stdout and writes its actual
findings to an output *directory* tree (``<output_dir>/results/<target>/scans/…``:
per-service nmap runs, enum output, and a consolidated report). A stdout-only
parser therefore captures almost nothing.

This collector walks that tree, folds the real result files back into the tool's
stdout (so the backend's registered parser — which keys off stdout — sees actual
nmap/service output), and returns a structured summary.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from _core.result import ToolResult

# Cap what we fold back so a huge engagement dir can't blow the context window.
_MAX_FILES = 40
_MAX_TOTAL_BYTES = 200_000
_MAX_FILE_BYTES = 40_000

# Files worth reading: nmap text output and the human-readable reports/notes.
_INTERESTING_RE = re.compile(
    r"(nmap.*\.txt|_commands\.log|notes\.md|local\.txt|.*_(tcp|udp)_.*\.txt)$",
    re.IGNORECASE,
)
_OUTDIR_RE = re.compile(r"-o\s+(\S+)")


def _output_dir_from_command(command: str) -> str:
    m = _OUTDIR_RE.search(command or "")
    return m.group(1) if m else "/tmp/autorecon"


def collect_autorecon_output(output_dir: str) -> tuple[str, dict[str, Any]]:
    """Return (consolidated_text, structured_summary) for an AutoRecon run dir."""
    root = Path(output_dir)
    if not root.exists():
        return "", {"findings": [], "note": f"autorecon output dir not found: {output_dir}"}

    picked: list[Path] = []
    for path in sorted(root.rglob("*")):
        if len(picked) >= _MAX_FILES:
            break
        if path.is_file() and _INTERESTING_RE.search(path.name):
            picked.append(path)

    chunks: list[str] = []
    total = 0
    files_read: list[str] = []
    for path in picked:
        if total >= _MAX_TOTAL_BYTES:
            break
        try:
            body = path.read_text(encoding="utf-8", errors="replace")[:_MAX_FILE_BYTES]
        except OSError:
            continue
        if not body.strip():
            continue
        rel = str(path.relative_to(root))
        chunks.append(f"----- {rel} -----\n{body}")
        files_read.append(rel)
        total += len(body)

    text = "\n\n".join(chunks)
    # Cheap structured summary — the authoritative findings come from the backend
    # parser re-reading the folded nmap text.
    open_ports = sorted(set(re.findall(r"^(\d+)/(?:tcp|udp)\s+open", text, re.MULTILINE)))
    summary = {
        "files_read": files_read,
        "open_ports": open_ports,
        "note": (
            f"AutoRecon: folded {len(files_read)} result file(s) from {output_dir} "
            f"into stdout for parsing." if files_read else
            f"AutoRecon produced no parseable result files under {output_dir}."
        ),
    }
    return text, summary


def parse(result: ToolResult) -> dict[str, Any]:
    """AutoRecon parse hook: fold directory results into stdout, return summary.

    Runs in-container (filesystem access) before ``ToolResult.to_dict()``, so
    appending to ``raw_stdout`` makes the collected output visible to the backend.
    """
    output_dir = _output_dir_from_command(result.command)
    text, summary = collect_autorecon_output(output_dir)
    if text:
        prefix = (result.raw_stdout or "").rstrip()
        result.raw_stdout = (
            f"{prefix}\n\n===== AUTORECON COLLECTED RESULTS ({output_dir}) =====\n{text}"
            if prefix
            else f"===== AUTORECON COLLECTED RESULTS ({output_dir}) =====\n{text}"
        )
    return summary
