"""Shell execution inside Kali (LLM think → execute).

Two modes (settings.enable_unrestricted_shell, default true):
- Unrestricted: command runs verbatim via `bash -c` in the container — loops,
  `;`, `&&`, `$()`, redirects all work (same as a raw shell).
- Gated: allowlisted argv only; simple pipes when every stage is allowlisted.
"""

from __future__ import annotations

import logging
import shlex
from fastapi import HTTPException

from osprey.schemas.tools import ToolExecutionResponse
from osprey.core.config import get_settings
from osprey.services.engagement_store import get_engagement_store
from osprey.services.mcp_client import get_mcp_client
from osprey.services.run_store import get_run_store
from osprey.services.session_context import resolve_session
from osprey.services.summary_agent import summarize_execution
from osprey.services.tool_coverage_store import get_tool_coverage_store

logger = logging.getLogger(__name__)

# Conservative allowlist — expand via settings later
DEFAULT_SHELL_ALLOWLIST = frozenset(
    {
        "nmap",
        "ncat",
        "subfinder",
        "httpx",
        "amass",
        "dnsenum",
        "fierce",
        "dig",
        "host",
        "whois",
        "curl",
        "wget",
        "nikto",
        "gobuster",
        "ffuf",
        "dirb",
        "whatweb",
        "wafw00f",
        "nuclei",
        "katana",
        "gau",
        "waybackurls",
        "hakrawler",
        "masscan",
        "rustscan",
        "naabu",
        "dnsx",
        "tlsx",
        "enum4linux",
        "smbclient",
        "rpcclient",
        "openssl",
        "python3",
        "python",
        "jq",
        "grep",
        "awk",
        "sed",
        "sort",
        "uniq",
        "head",
        "tail",
        "cut",
        "tr",
        "cat",
        "echo",
        "printf",
        "wc",
        "testssl.sh",
        "sslscan",
        "whoami",
        "ping",
        "ping6",
        "traceroute",
        "ip",
        "ifconfig",
        "nslookup",
        "date",
        "uname",
        "id",
        "env",
        "pwd",
        "ls",
        "ps",
        "kill",
        "chmod",
        "tee",
        "mkdir",
        "rm",
        "mv",
        "cp",
        "touch",
        "tee",
        "timeout",
        "sleep",
        "xargs",
        "find",
        "diff",
        "comm",
        "tee",
        "yes",
        "false",
        "true",
    }
)

# Gated-mode restrictions only (unrestricted mode passes raw bash -c).
# Still blocked: ; & ` $ () <> and newlines (command injection / redirect).
# Pipes | are allowed when EVERY stage binary is allowlisted.
_BLOCKED_METACHAR = set(";`$()<>\n\r")


def _mask_quoted(text: str) -> str:
    """Replace quoted spans with a neutral char so metacharacter checks below
    only see what the shell would actually treat as unquoted (and thus
    dangerous) — a quoted `$1` in ``awk '{print $1}'`` or a quoted `(foo|bar)`
    in ``grep -E '(foo|bar)'`` is inert shell-wise and shouldn't be rejected
    just because the RAW string happens to contain the character.
    """
    out: list[str] = []
    in_single = False
    in_double = False
    for ch in text:
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
        elif in_single or in_double:
            out.append("x")
        else:
            out.append(ch)
    return "".join(out)


def _split_pipeline(command: str) -> list[str]:
    """Split on bare | (not inside quotes)."""
    parts: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    i = 0
    text = command
    while i < len(text):
        ch = text[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
        elif ch == "|" and not in_single and not in_double:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def validate_shell_command(command: str, allowlist: frozenset[str] | None = None) -> list[str]:
    """
    Validate allowlisted argv. Supports simple pipes:
      curl -sI https://x | grep -i server
    when every stage binary is allowlisted. No ; & redirects or $().
    Returns flattened argv for single-stage, or the original tokens joined
    for pipeline execution via bash -c with a rebuilt safe pipeline.
    """
    text = (command or "").strip()
    if not text:
        raise ValueError("command is empty")
    # Check UNQUOTED content only — a quoted `$1` (awk '{print $1}') or a
    # quoted `(foo|bar)` (grep -E '(foo|bar)') is inert shell-wise and must
    # not be rejected just because the raw string contains the character.
    scan_text = _mask_quoted(text)
    if any(c in scan_text for c in _BLOCKED_METACHAR):
        raise ValueError(
            "Shell metacharacters (;`$()<>) are not allowed in platform_shell. "
            "Pipes | are OK if each binary is allowlisted. "
            "For loops/redirects/complex logic — use platform_script."
        )
    # Disallow & background / && / ||
    if "&&" in scan_text or "||" in scan_text or scan_text.endswith("&"):
        raise ValueError("&& || and background & are not allowed — use platform_script")

    allowed = allowlist or DEFAULT_SHELL_ALLOWLIST
    stages = _split_pipeline(text)
    if not stages:
        raise ValueError("command is empty after parse")

    rebuilt: list[str] = []
    for stage in stages:
        try:
            argv = shlex.split(stage)
        except ValueError as exc:
            raise ValueError(f"Could not parse command stage: {exc}") from exc
        if not argv:
            raise ValueError("empty pipeline stage")
        binary = argv[0].rsplit("/", 1)[-1]
        if binary not in allowed:
            raise ValueError(
                f"Binary '{binary}' is not allowlisted. "
                f"Use platform_exec / platform_script, or request allowlist expansion."
            )
        rebuilt.append(shlex.join(argv))

    # Single stage → return argv list for run_argv
    if len(rebuilt) == 1:
        return shlex.split(stages[0])

    # Pipeline → return special form consumed by execute_shell_request
    return ["__pipeline__", " | ".join(rebuilt)]


async def execute_shell_request(
    *,
    command: str,
    engagement_id: str | None = None,
    run_id: str | None = None,
    reason: str = "",
    timeout: int = 180,
    record_findings: bool = True,
) -> ToolExecutionResponse:
    """Run a shell command in Kali.

    Unrestricted mode (default, `enable_unrestricted_shell=true`): the command
    is passed verbatim to `bash -c` inside the container — loops, `;`, `&&`,
    `$()`, redirects all work (same capability as a raw shell).
    Gated mode (`enable_unrestricted_shell=false`): allowlisted argv only.
    """
    settings = get_settings()
    if settings.enable_unrestricted_shell:
        raw_command = (command or "").strip()
        if not raw_command:
            raise HTTPException(status_code=400, detail="command is empty")
        if len(raw_command) > 50000:
            raise HTTPException(status_code=400, detail="command too long (max 50000 chars)")
        argv: list[str] | None = None
        pipeline: str | None = None
    else:
        try:
            argv = validate_shell_command(command)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        raw_command = None
        pipeline = argv[1] if argv and argv[0] == "__pipeline__" else None

    session = resolve_session(engagement_id=engagement_id, run_id=run_id, seed_target="")
    if not session.engagement_id:
        raise HTTPException(
            status_code=400,
            detail="engagement_id required — call platform_set_target first",
        )
    eng = get_engagement_store().get(session.engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail=f"Engagement not found: {session.engagement_id}")
    if session.run_id:
        get_run_store().ensure(run_id=session.run_id, engagement_id=session.engagement_id)

    timeout = max(30, min(int(timeout), 900))
    mcp = get_mcp_client()

    if settings.enable_unrestricted_shell:
        printable = raw_command
        logger.info("shell bash engagement=%s reason=%s cmd=%s", session.engagement_id, reason, printable[:400])
        response = await mcp.run_argv(
            ["bash", "-c", raw_command],
            timeout=timeout,
            tool_name="shell:bash",
        )
        response.command = raw_command
        response.hybrid = {
            "shell": True,
            "unrestricted": True,
            "reason": reason,
            "note": "Unrestricted bash -c — loops/;/&&/$()/redirects allowed (execute_shell_request unrestricted mode).",
        }
    elif pipeline is not None:
        printable = pipeline
        logger.info("shell pipeline engagement=%s reason=%s cmd=%s", session.engagement_id, reason, printable)
        # bash -c with rebuilt shlex-joined stages only (no raw user metachar injection)
        response = await mcp.run_argv(
            ["bash", "-c", pipeline],
            timeout=timeout,
            tool_name="shell:pipeline",
        )
        response.command = pipeline
        response.hybrid = {
            "shell": True,
            "pipeline": True,
            "reason": reason,
            "note": "Allowlisted pipeline — each stage binary checked. Prefer platform_script for complex logic.",
        }
    else:
        printable = " ".join(shlex.quote(a) for a in argv)
        logger.info("shell exec engagement=%s reason=%s cmd=%s", session.engagement_id, reason, printable)
        response = await mcp.run_argv(argv, timeout=timeout, tool_name=f"shell:{argv[0]}")
        response.command = printable
        response.hybrid = {
            "shell": True,
            "reason": reason,
            "argv": argv,
            "note": "Allowlisted shell — parsers best-effort; raw stdout always stored. Pipes OK if all binaries allowlisted.",
        }

    if record_findings:
        try:
            findings = await summarize_execution(
                response,
                engagement_id=session.engagement_id,
                run_id=session.run_id or run_id or "",
                target=eng.target,
                phase="",
                force_raw_observation=True,
            )
            from osprey.services.ingest_promoter import apply_ingest_rules

            ingested = apply_ingest_rules(
                response.stdout or "",
                response.stderr or "",
                engagement_id=session.engagement_id,
                run_id=session.run_id or run_id or "",
                source_tool=response.tool_name,
                target=eng.target,
                persist=True,
            )
            titles = [f.title for f in findings] + [f.title for f in ingested]
            response.finding_titles = list(dict.fromkeys(titles))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Findings ingest failed for %s: %s", response.tool_name, exc)
        try:
            get_tool_coverage_store().record(
                engagement_id=session.engagement_id,
                tool_name=response.tool_name,
                asset=eng.target,
                run_id=session.run_id or "",
                findings_count=len(response.finding_titles or []),
                success=bool(response.success),
                notes=reason or "shell exec",
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Tool coverage record skip: %s", exc)
        try:
            get_engagement_store().increment_tools_executed(session.engagement_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Tools executed increment skip: %s", exc)

    return response
