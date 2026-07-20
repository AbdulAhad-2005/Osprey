"""Pluggable failure/success hint providers — register once, run everywhere."""



from __future__ import annotations



from dataclasses import dataclass

from typing import Callable



HintProvider = Callable[["HintContext"], list[str]]



_REGISTRY: list[tuple[int, HintProvider]] = []





@dataclass

class HintContext:

    tool_name: str

    command: str

    stdout: str

    stderr: str

    error: str

    phase: str

    success: bool

    timed_out: bool = False





def register_hint_provider(provider: HintProvider, *, priority: int = 50) -> None:

    _REGISTRY.append((priority, provider))

    _REGISTRY.sort(key=lambda item: item[0])





def collect_hints(ctx: HintContext) -> list[str]:

    hints: list[str] = []

    seen: set[str] = set()

    for _, provider in _REGISTRY:

        for hint in provider(ctx):

            if hint not in seen:

                seen.add(hint)

                hints.append(hint)

    return hints





def _hints_container_and_privilege(ctx: HintContext) -> list[str]:

    blob = f"{ctx.command}\n{ctx.stdout}\n{ctx.stderr}\n{ctx.error}".lower()

    hints: list[str] = []

    if "sudo" in blob and "password" in blob:

        hints.append(

            "HINT: Tool invoked sudo but the Kali container has no interactive TTY. "

            "Use a tool that does not require sudo, or call the underlying binary directly."

        )

    if "raw socket" in blob or "operation not permitted" in blob or "couldn't open a raw socket" in blob:

        hints.append(

            "HINT: SYN/raw scan is blocked in this container. "

            "Retry with TCP connect scan: -sT -Pn --unprivileged."

        )

    return hints





def _hints_target_shape(ctx: HintContext) -> list[str]:

    blob = f"{ctx.command}\n{ctx.stdout}\n{ctx.stderr}\n{ctx.error}".lower()

    hints: list[str] = []

    if "not an ip address" in blob or "not an ip address or address range" in blob:

        hints.append(

            "HINT: This tool requires a literal IPv4 address. "

            "Use RESOLVED_IP from system context or resolve from prior tool output."

        )

    if ctx.tool_name == "nbtscan_netbios" and "not an ip" in blob:

        hints.append("HINT: Pass RESOLVED_IP instead of the hostname for nbtscan_netbios.")

    return hints





def _hints_timeout_and_ports(ctx: HintContext) -> list[str]:

    blob = f"{ctx.command}\n{ctx.stdout}\n{ctx.stderr}\n{ctx.error}".lower()

    hints: list[str] = []

    if ctx.timed_out or "timed out" in blob:

        if any(x in ctx.command for x in ("65535", "-p-", "1-65535")):

            hints.append(

                "HINT: Full-port scan exceeded the time limit. "

                "Use --top-ports 1000 or scan known open ports from prior findings."

            )

    return hints





def _hints_tool_specific(ctx: HintContext) -> list[str]:

    blob = f"{ctx.command}\n{ctx.stdout}\n{ctx.stderr}\n{ctx.error}".lower()

    hints: list[str] = []



    if ctx.tool_name == "amass_scan" and (

        "passive" in ctx.command.split()[:2] or ctx.command.strip() == "amass passive"

    ):

        hints.append(

            "HINT: amass passive mode must include the domain: "

            "use mode=enum with additional_args '-passive', or amass enum -passive -d <domain>."

        )



    if ctx.tool_name in ("enum4linux_scan", "enum4linux_ng_advanced") and (

        "connection refused" in blob

        or "do not exist" in blob

        or "cannot obtain" in blob

        or "session setup failed" in blob

    ):

        hints.append(

            "HINT: No SMB/NetBIOS service on this target (typical for Linux hosts). "

            "Skip SMB enumeration and move to what the evidence supports next."

        )

    return hints





def _hints_fallback(ctx: HintContext) -> list[str]:

    if ctx.success:

        return []

    return [

        "HINT: Read STDERR/ERROR above, change approach based on CURRENT SITUATION, "

        "and do not repeat the same failing command."

    ]





def _register_builtins() -> None:

    register_hint_provider(_hints_container_and_privilege, priority=10)

    register_hint_provider(_hints_target_shape, priority=20)

    register_hint_provider(_hints_timeout_and_ports, priority=30)

    register_hint_provider(_hints_tool_specific, priority=40)

    register_hint_provider(_hints_fallback, priority=100)





_register_builtins()





def build_failure_hints(

    *,

    tool_name: str,

    command: str,

    stdout: str,

    stderr: str,

    error: str,

    phase: str = "",

    success: bool = False,

    timed_out: bool = False,

) -> str:

    """Backward-compatible entry — delegates to registered providers."""

    ctx = HintContext(

        tool_name=tool_name,

        command=command,

        stdout=stdout,

        stderr=stderr,

        error=error,

        phase=phase,

        success=success,

        timed_out=timed_out,

    )

    hints = collect_hints(ctx)

    return "\n".join(hints)


