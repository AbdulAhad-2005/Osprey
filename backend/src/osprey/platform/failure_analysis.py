"""Generic tool failure analysis — helps the LLM diagnose and fix before pivoting."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

FailureAnalyzer = Callable[["FailureContext"], "FailureDiagnosis | None"]

_REGISTRY: list[tuple[int, FailureAnalyzer]] = []

_USAGE_RE = re.compile(
    r"(usage:|unrecognized option|invalid option|unknown option|"
    r"error:|fatal:|must specify|required argument|missing required)",
    re.I,
)
_VERSION_ONLY_RE = re.compile(r"version[:\s]*[\d.]+", re.I)


@dataclass
class FailureContext:
    tool_name: str
    command: str
    stdout: str
    stderr: str
    error: str
    returncode: int | None
    timed_out: bool
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class FailureDiagnosis:
    category: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    likely_causes: list[str] = field(default_factory=list)
    fix_options: list[str] = field(default_factory=list)  # hypotheses — LLM chooses


def register_failure_analyzer(analyzer: FailureAnalyzer, *, priority: int = 50) -> None:
    _REGISTRY.append((priority, analyzer))
    _REGISTRY.sort(key=lambda item: item[0])


def analyze_failure(ctx: FailureContext) -> FailureDiagnosis | None:
    if ctx.timed_out:
        return FailureDiagnosis(
            category="timeout",
            summary="Tool run exceeded the time limit before completing.",
            evidence=[f"COMMAND: {ctx.command}"],
            likely_causes=[
                "Scan scope too wide (e.g. full port range)",
                "Target slow or filtering probes",
            ],
            fix_options=[
                "Narrow scope: top ports, single host, or flags from prior findings",
                "Retry with faster timing template if appropriate",
            ],
        )

    diagnoses: list[FailureDiagnosis] = []
    for _, analyzer in _REGISTRY:
        result = analyzer(ctx)
        if result is not None:
            diagnoses.append(result)

    if not diagnoses and _is_failed(ctx):
        return _generic_failure(ctx)

    if not diagnoses:
        return None

    return _merge_diagnoses(diagnoses)


def format_failure_analysis(
    ctx: FailureContext,
    *,
    diagnosis: FailureDiagnosis | None = None,
) -> str:
    diag = diagnosis or analyze_failure(ctx)
    if diag is None:
        return ""

    lines = [
        "FAILURE ANALYSIS (structured context — you decide the response; nothing runs automatically):",
        f"Observed: {diag.summary}",
    ]
    if diag.evidence:
        lines.append("Evidence from this run:")
        lines.extend(f"  - {item}" for item in diag.evidence[:8])
    if diag.likely_causes:
        lines.append("Plausible explanations (may be wrong — weigh against full output):")
        lines.extend(f"  - {item}" for item in diag.likely_causes[:5])
    if diag.fix_options:
        lines.append("Angles to consider (not a script — adapt for this target):")
        for item in diag.fix_options[:4]:
            lines.append(f"  - {item}")
    lines.append(
        "Your job: reason from the evidence above, then retry with a changed approach, "
        "pivot to another tool, or document why this check does not apply."
    )
    return "\n".join(lines)


def _is_failed(ctx: FailureContext) -> bool:
    if ctx.timed_out:
        return True
    if ctx.returncode not in (None, 0):
        return True
    if ctx.error:
        return True
    return False


def _meaningful_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def _tail_evidence(ctx: FailureContext, *, max_lines: int = 4) -> list[str]:
    evidence: list[str] = []
    out_lines = _meaningful_lines(ctx.stdout)
    err_lines = _meaningful_lines(ctx.stderr)
    if out_lines:
        for line in out_lines[-max_lines:]:
            evidence.append(f"STDOUT: {line[:200]}")
    if err_lines:
        for line in err_lines[-max_lines:]:
            evidence.append(f"STDERR: {line[:200]}")
    if ctx.error:
        evidence.append(f"ERROR: {ctx.error[:200]}")
    if ctx.returncode is not None:
        evidence.append(f"Exit code: {ctx.returncode}")
    if not evidence:
        evidence.append("No useful output captured — check COMMAND and tool parameters")
    return evidence


def _analyze_usage_error(ctx: FailureContext) -> FailureDiagnosis | None:
    blob = f"{ctx.stdout}\n{ctx.stderr}\n{ctx.error}"
    if not _USAGE_RE.search(blob):
        return None
    fix_lines = _meaningful_lines(ctx.stderr) or _meaningful_lines(ctx.stdout)
    usage_hint = next((ln for ln in fix_lines if _USAGE_RE.search(ln)), "")
    return FailureDiagnosis(
        category="usage_error",
        summary="Tool rejected the command — likely wrong or incomplete flags.",
        evidence=_tail_evidence(ctx),
        likely_causes=[
            "Missing required argument or mode flag",
            "Flag syntax incompatible with this tool version",
        ],
        fix_options=[
            f"Retry {ctx.tool_name} with corrected additional_args"
            + (f" (see: {usage_hint[:120]})" if usage_hint else ""),
            "Compare COMMAND against the tool's expected invocation from your training",
            "If the tool cannot be fixed quickly, use an equivalent tool for the same goal",
        ],
    )


def _analyze_incomplete_invocation(ctx: FailureContext) -> FailureDiagnosis | None:
    if ctx.returncode in (None, 0):
        return None
    out_lines = _meaningful_lines(ctx.stdout)
    err_lines = _meaningful_lines(ctx.stderr)
    if len(out_lines) > 4 or len(err_lines) > 2:
        return None
    if out_lines and all(_VERSION_ONLY_RE.search(ln) or len(ln) < 20 for ln in out_lines):
        summary = "Tool printed only a banner/version line then exited — it never started real work."
    elif not out_lines and not err_lines:
        summary = "Tool failed immediately with almost no output."
    else:
        summary = "Tool failed with very little output — invocation probably incomplete."

    return FailureDiagnosis(
        category="incomplete_invocation",
        summary=summary,
        evidence=_tail_evidence(ctx),
        likely_causes=[
            "COMMAND is missing mode flags the tool requires before it runs",
            "Wrong parameter shape (domain vs IP, URL vs host, file path missing)",
            "Tool expects subcommand or --enum/-d/-u style flags in additional_args",
        ],
        fix_options=[
            f"Same tool ({ctx.tool_name}) with different additional_args if the invocation looks wrong",
            "Different tool or technique if this failure pattern does not fit the target",
            "Your own interpretation if the evidence points somewhere else",
        ],
    )


def _analyze_privilege(ctx: FailureContext) -> FailureDiagnosis | None:
    blob = f"{ctx.command}\n{ctx.stdout}\n{ctx.stderr}\n{ctx.error}".lower()
    if not any(
        phrase in blob
        for phrase in (
            "operation not permitted",
            "raw socket",
            "permission denied",
            "must be root",
            "sudo",
        )
    ):
        return None
    return FailureDiagnosis(
        category="privilege",
        summary="Tool failed due to container privilege limits.",
        evidence=_tail_evidence(ctx),
        likely_causes=["Raw sockets, sudo, or CAP_NET_RAW not available in this environment"],
        fix_options=[
            "Use an unprivileged alternative (e.g. nmap -sT -Pn --unprivileged)",
            "Avoid sudo-only tools in this container",
        ],
    )


def _analyze_target_shape(ctx: FailureContext) -> FailureDiagnosis | None:
    blob = f"{ctx.stdout}\n{ctx.stderr}\n{ctx.error}".lower()
    if "not an ip address" not in blob and "not an ip address or address range" not in blob:
        return None
    return FailureDiagnosis(
        category="target_shape",
        summary="Tool rejected the target format.",
        evidence=_tail_evidence(ctx),
        likely_causes=["This tool requires a literal IPv4, not a hostname"],
        fix_options=[
            "Use RESOLVED_IP from context instead of the hostname",
            "Resolve IP from prior DNS/nmap output before retrying",
        ],
    )


def _analyze_unreachable(ctx: FailureContext) -> FailureDiagnosis | None:
    blob = f"{ctx.stdout}\n{ctx.stderr}\n{ctx.error}".lower()
    if not any(
        phrase in blob
        for phrase in ("connection refused", "no route to host", "host unreachable", "timed out")
    ):
        return None
    return FailureDiagnosis(
        category="unreachable",
        summary="Target or service appears unreachable from the scanner.",
        evidence=_tail_evidence(ctx),
        likely_causes=["Host down, filtered, or wrong IP/port", "Network path blocked from container"],
        fix_options=[
            "Verify target is correct and in scope",
            "Try a lighter probe or a different port/protocol",
        ],
    )


def _generic_failure(ctx: FailureContext) -> FailureDiagnosis:
    return FailureDiagnosis(
        category="tool_failure",
        summary=f"{ctx.tool_name} failed — output above explains why.",
        evidence=_tail_evidence(ctx),
        likely_causes=[
            "Wrong flags, wrong target shape, or environment limitation",
            "Tool-specific prerequisite missing (wordlist, IP, auth)",
        ],
        fix_options=[
            f"Re-read STDOUT/STDERR and fix the invocation, then retry {ctx.tool_name}",
            "If unfixable, pivot to a different tool that achieves the same goal",
        ],
    )


def _merge_diagnoses(items: list[FailureDiagnosis]) -> FailureDiagnosis:
    primary = items[0]
    causes: list[str] = []
    fixes: list[str] = []
    evidence: list[str] = []
    for item in items:
        causes.extend(item.likely_causes)
        fixes.extend(item.fix_options)
        evidence.extend(item.evidence)
    return FailureDiagnosis(
        category=primary.category,
        summary=primary.summary,
        evidence=list(dict.fromkeys(evidence))[:8],
        likely_causes=list(dict.fromkeys(causes))[:5],
        fix_options=list(dict.fromkeys(fixes))[:4],
    )


def _analyze_nmap_ports(ctx: FailureContext) -> FailureDiagnosis | None:
    blob = f"{ctx.stdout}\n{ctx.stderr}\n{ctx.error}"
    if "port specifications are illegal" not in blob.lower():
        return None
    return FailureDiagnosis(
        category="param_shape",
        summary="Nmap rejected the port list — the ports parameter must be numbers only, not -p flags.",
        evidence=_tail_evidence(ctx),
        likely_causes=[
            "ports was set to '-p22,80' instead of '22,80,443'",
            "command_builder adds -p automatically; pass comma-separated port numbers only",
        ],
        fix_options=[
            f"Retry {ctx.tool_name} with ports='22,80,443' (no -p prefix)",
            "Or use nmap_custom_scan with flags='--top-ports 1000' for broader coverage",
        ],
    )


def _register_builtins() -> None:
    register_failure_analyzer(_analyze_usage_error, priority=10)
    register_failure_analyzer(_analyze_nmap_ports, priority=12)
    register_failure_analyzer(_analyze_incomplete_invocation, priority=20)
    register_failure_analyzer(_analyze_privilege, priority=30)
    register_failure_analyzer(_analyze_target_shape, priority=40)
    register_failure_analyzer(_analyze_unreachable, priority=50)


_register_builtins()
