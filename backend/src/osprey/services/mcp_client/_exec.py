"""MCPClient tool-invocation + docker-exec methods (mixin)."""

from __future__ import annotations
import asyncio
import os
import time
import uuid
from typing import Any
from osprey.schemas.tools import (
    MCPServerCategory,
    ToolDefinition,
    ToolExecutionResponse,
)
from osprey.services.tool_registry import get_tool_definition
from osprey.services.mcp_client._helpers import (
    logger,
    _KALI_ENV_FORWARD,
    _KALI_EXEC_PATH,
    _truncate_stdout,
    _kill_and_reap,
    _drain_partial,
    _parse_tool_output,
    MCPClientError,
)


class _DockerExecMixin:

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def call_tool(
        self,
        tool_name: str,
        params: dict[str, Any],
        *,
        timeout: int = 300,
        prebuilt_command: str | None = None,
    ) -> ToolExecutionResponse:
        """Execute a tool via the appropriate MCP server.

        ``prebuilt_command``, when given, is the exact command string to run —
        callers that already built (and fail-fast-validated) the command via
        ``build_command_for_tool`` pass it through here so it is built once per
        request instead of once for validation and again for execution. Only
        the docker-exec path consumes it; the MCP-stdio path sends structured
        params and has no second build to collapse.

        This sends a ``tools/call`` JSON-RPC request over stdio and
        returns a normalized response.
        """
        tool_def = get_tool_definition(tool_name)
        if tool_def is None:
            raise MCPClientError(f"Unknown tool: {tool_name}")

        server_category = tool_def.mcp_server

        # If docker exec approach, run the tool directly without MCP protocol
        if self._use_docker and self._is_docker_available():
            return await self._call_via_docker_exec(
                tool_name, tool_def, params, timeout, prebuilt_command=prebuilt_command
            )

        # Otherwise use MCP stdio protocol
        request_id = id(params) % 100000
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": params,
            },
        }

        # One in-flight request/response per shared stdio server (see __init__).
        # `ensure_server()` is (re-)fetched HERE, inside the lock, not before it —
        # a caller that fetched it earlier and then waited to acquire the lock
        # could be holding a reference to a process a different caller already
        # killed-and-reaped (see the except branches below) while it waited. Only
        # one caller is ever inside this lock for this category at a time, so
        # re-fetching here is always the current, live process, never stale.
        req_lock = self._req_locks.setdefault(server_category, asyncio.Lock())
        started = time.monotonic()
        try:
            async with req_lock:
                proc = await self.ensure_server(server_category)
                response_bytes = await self._send_and_receive(proc, request, timeout)
            response = self._parse_response(tool_name, response_bytes)
            response.duration_seconds = time.monotonic() - started
            return response
        except asyncio.TimeoutError:
            # The server is very likely still blocked finishing THIS request
            # internally (its own tool call hasn't returned yet) — releasing the
            # lock here without killing the process would let the NEXT caller's
            # write land on the same stdin while the old request is still being
            # worked, and that caller's readline() can then receive THIS
            # request's late, straggling response instead of its own (permanent
            # request/response desync for every later call on this pipe — the
            # cross-tool response leaks that produced e.g. a whois_lookup call
            # returning a stale dnsenum_scan result). Kill + drop the shared
            # process so the next call spawns a fresh, correctly-aligned one —
            # the same recovery the docker-exec timeout path already uses.
            await self._kill_and_reap_server(server_category)
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                error=f"MCP server timed out after {timeout}s",
                timed_out=True,
            )
        except Exception as exc:
            logger.exception("MCP call failed for %s", tool_name)
            # Any other failure on this shared pipe (a malformed/partial write,
            # a corrupted response line) leaves the stream's alignment for
            # subsequent calls unverifiable too — restart it defensively rather
            # than risk the same cross-tool leak on the next caller.
            await self._kill_and_reap_server(server_category)
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                error=str(exc),
            )

    async def _kill_and_reap_server(self, server_category: MCPServerCategory) -> None:
        """Kill and forget the shared persistent process for *server_category*
        (native/stdio mode only) so the next call spawns a fresh one instead of
        risking a desynced request/response stream."""
        proc = self._processes.pop(server_category, None)
        if proc is not None:
            await _kill_and_reap(proc)

    async def _kill_remote_process_group(self, pidfile: str) -> None:
        """On a docker-exec timeout, killing the LOCAL docker-exec client process
        (``_kill_and_reap``) does NOT terminate the REMOTE command still running
        inside the Kali container — a local SIGKILL to the docker CLI client is
        not proxied into the exec session, so the actual scan is orphaned and
        keeps running.

        The exec'd command is started under ``setsid`` and records its own pid
        to ``pidfile`` before running (see ``_exec_docker_once``), so this can
        reach the whole process group it heads — including children the tool
        itself forks (dnsenum/amass do) — with one more docker-exec call.
        Best-effort: never raises, never blocks more than a few seconds.
        """
        try:
            kill_cmd = (
                f'P=$(cat {pidfile} 2>/dev/null); '
                f'[ -n "$P" ] && kill -TERM -"$P" 2>/dev/null; '
                f'sleep 1; '
                f'[ -n "$P" ] && kill -KILL -"$P" 2>/dev/null; '
                f'rm -f {pidfile}'
            )
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", "-i", self._kali_container, "bash", "-c", kill_cmd,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=8.0)
        except Exception:
            logger.warning("Remote process-group kill for %s failed (best-effort)", pidfile, exc_info=True)

    async def _exec_docker_once(
        self, command: str, timeout: int, *, run_as_root: bool = False
    ) -> tuple[str, str, int | None, bool, float]:
        """One docker-exec attempt. Returns (stdout, stderr, returncode, timed_out,
        duration_seconds) — never raises for a timeout (drains partial output
        instead), so the retry loop above has a uniform result shape to make a
        decision on. ``duration_seconds`` is real wall-clock time around the
        subprocess, not a placeholder — every ``ToolExecutionResponse`` this
        feeds needs it to be real for the CLI/dashboard to ever distinguish a
        genuine re-execution from a cache hit or a replayed event (it was
        hardcoded to 0 everywhere before; see plan 19)."""
        started = time.monotonic()
        proc: asyncio.subprocess.Process | None = None
        # Create a unique pidfile to track this command's process group for targeted timeout kills.
        # `setsid` makes the shell a new session leader. Capturing `$$` before execution remains valid
        # post-`exec` and includes any sub-processes. $RC preserves the command's original exit code.
        #
        # MUST use `setsid -w`: without waiting, `setsid` forks and exits immediately, causing `docker exec`
        # to report instant success while the command continues running detached in the background.#

        pidfile = f"/tmp/.osprey-exec-{uuid.uuid4().hex}.pid"
        wrapped_command = f"echo $$ > {pidfile}; {command}; RC=$?; rm -f {pidfile}; exit $RC"
        try:
            docker_argv = ["docker", "exec", "-i"]
            if run_as_root:
                # Privileged tools (nmap -sS/-O, masscan, arp-scan, responder)
                # need raw sockets / NET_RAW the unprivileged mcpuser lacks.
                # Capability-based: only tools the registry marked requires_root
                # (or a caller-requested privileged flag) get -u 0 — everything
                # else stays unprivileged.
                docker_argv += ["-u", "0"]
            for env_key in _KALI_ENV_FORWARD:
                env_val = (os.getenv(env_key) or "").strip()
                if env_val:
                    docker_argv.extend(["-e", f"{env_key}={env_val}"])
            docker_argv.extend([self._kali_container, "setsid", "-w", "bash", "-c", wrapped_command])

            proc = await asyncio.create_subprocess_exec(
                *docker_argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            stdout = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
            return stdout, stderr, proc.returncode, False, time.monotonic() - started
        except asyncio.TimeoutError:
            partial_stdout, partial_stderr = await _drain_partial(proc)
            await _kill_and_reap(proc)
            await self._kill_remote_process_group(pidfile)
            return partial_stdout, partial_stderr, None, True, time.monotonic() - started

    async def _call_via_docker_exec(
        self,
        tool_name: str,
        tool_def: ToolDefinition,
        params: dict[str, Any],
        timeout: int,
        *,
        prebuilt_command: str | None = None,
    ) -> ToolExecutionResponse:
        """Run a tool directly via docker exec without MCP protocol.

        Builds the CLI command from the tool's build_command pattern (unless
        ``prebuilt_command`` is supplied, in which case that exact string is
        used verbatim — see ``call_tool``) and executes it inside the
        kali-tools container, with a bounded real retry loop on failure —
        classification + strategy decision comes from
        execution_recovery.real_retry_decision() (a bridge to the platform's
        already-built recovery engine, which was previously
        wired but architecturally unreachable from this exact path: it only
        ever ran when a tool module's own run()/run_tool() was invoked
        directly, which this docker-exec path never did). Retry mechanics
        (subprocess handling, timeouts) stay here since this method already
        owns them; only the "what to do about a failure" decision is
        delegated.
        """
        from osprey.services.command_builder import build_command_for_tool
        from osprey.services.execution_recovery import real_retry_decision
        from osprey.services.task_registry import get_tool_capability

        params_copy = params.copy()
        additional_args = str(params_copy.pop("additional_args", "") or "")
        cap = get_tool_capability(tool_name)
        freeform_field = cap.freeform_args_field if cap else "additional_args"
        target = str(params_copy.get("target", params_copy.get("domain", "unknown")))

        # Privilege decision: registry-declared root need wins; a per-call
        # privileged=true/run_as_root=true param (nmap_custom_scan's escape
        # hatch) also opts in. Both go through the same docker exec -u 0 path.
        run_as_root = bool(getattr(tool_def, "requires_root", False))
        if not run_as_root:
            run_as_root = str(params_copy.get("privileged", "") or "").strip().lower() in (
                "true", "1", "yes",
            )
            run_as_root = run_as_root or str(params_copy.get("run_as_root", "") or "").strip().lower() in (
                "true", "1", "yes",
            )
        params_copy.pop("privileged", None)
        params_copy.pop("run_as_root", None)

        if prebuilt_command is not None:
            command = prebuilt_command
        else:
            try:
                command = build_command_for_tool(
                    tool_name,
                    params_copy,
                    additional_args=additional_args,
                    tool_def=tool_def,
                    freeform_field=freeform_field,
                )
            except (ValueError, OSError) as exc:
                return ToolExecutionResponse(tool_name=tool_name, success=False, error=str(exc))

        # `docker exec ... bash -c` is a NON-login shell, so it does not pick up
        # ~/.local/bin (pip --user) or pipx shims from the mcpuser login profile.
        # Many OSINT tools (maigret/holehe/social-analyzer via pipx, plus any
        # runtime `platform_install` pip --user) live there. Prepend those dirs so
        # they resolve exactly like the apt/go tools already on the image PATH.
        command = f'export PATH="{_KALI_EXEC_PATH}"; {command}'

        max_attempts = 3
        recovery_history: list[dict[str, Any]] = []
        alternative_tool: str | None = None
        final_action = "all_attempts_exhausted"
        attempt = 0

        try:
            while True:
                attempt += 1
                logger.info("Executing in kali-tools (attempt %d): %s", attempt, command)
                stdout, stderr, returncode, timed_out, attempt_duration = await self._exec_docker_once(
                    command, timeout, run_as_root=run_as_root
                )

                if returncode == 0 and not timed_out:
                    parsed_data = _parse_tool_output(
                        tool_def, command=command, returncode=returncode, stdout=stdout, stderr=stderr
                    )
                    response = ToolExecutionResponse(
                        tool_name=tool_name,
                        success=True,
                        command=command,
                        returncode=returncode,
                        stdout=_truncate_stdout(stdout, tool_name),
                        stderr=stderr[:10000],
                        parsed=parsed_data,
                        duration_seconds=attempt_duration,
                    )
                    if recovery_history:
                        response.recovery_info = {
                            "attempts_made": attempt,
                            "recovery_applied": True,
                            "recovery_history": recovery_history,
                        }
                    return response

                error_message = stderr or (f"Execution timed out after {timeout}s" if timed_out else "Unknown error")

                if attempt >= max_attempts:
                    final_action = "all_attempts_exhausted"
                    break

                decision = real_retry_decision(
                    tool_name=tool_name,
                    command=command,
                    params=params_copy,
                    error_message=error_message,
                    target=target,
                    attempt_count=attempt,
                    timed_out=timed_out,
                )
                if decision is None:
                    final_action = "recovery_engine_unavailable"
                    break

                if decision.get("alternative_tool"):
                    alternative_tool = str(decision["alternative_tool"])

                if not decision.get("should_retry"):
                    recovery_history.append(
                        {
                            "attempt": attempt,
                            "error": error_message[:500],
                            "recovery_action": decision["recovery_action"],
                            "error_type": decision.get("error_type"),
                        }
                    )
                    final_action = decision["recovery_action"]
                    break

                rebuilt_command = decision.get("rebuilt_command") or command
                # A retry after a TIMEOUT that doesn't actually change the
                # command is guaranteed to time out again, identically — the
                # exact same invocation against the exact same slow target.
                # error_handler.py's per-tool flag-rewriting only covers a
                # handful of tools (nmap/gobuster/nuclei/feroxbuster/ffuf);
                # for everything else (e.g. dnsenum — the tool that
                # originally surfaced this) the "reduced scope" adjustment is
                # silently a no-op, so `should_retry=True` was burning a full
                # extra `timeout` (or two, at max_attempts=3) for zero chance
                # of a different outcome — the mechanism this investigation
                # opportunity's timeout ceiling exists to bound. Same
                # principle as tool_execution.py's auto-fallback guard: a
                # same-invocation retry must change something to be worth
                # attempting.
                if timed_out and rebuilt_command == command:
                    recovery_history.append(
                        {
                            "attempt": attempt,
                            "error": error_message[:500],
                            "recovery_action": "retry_skipped_identical_after_timeout",
                            "error_type": decision.get("error_type"),
                        }
                    )
                    final_action = "retry_skipped_identical_after_timeout"
                    break
                recovery_history.append(
                    {
                        "attempt": attempt,
                        "error": error_message[:500],
                        "recovery_action": decision["recovery_action"],
                        "error_type": decision.get("error_type"),
                    }
                )
                backoff = float(decision.get("backoff_seconds") or 0.0)
                if backoff > 0:
                    await asyncio.sleep(min(backoff, 60.0))
                command = rebuilt_command

            # Exhausted retries (or the decision said stop) — return the last
            # real attempt's result, with the alternative-tool suggestion and
            # full recovery_history attached so the caller sees genuine,
            # already-tried history instead of guessing from scratch.
            parsed_data = _parse_tool_output(
                tool_def,
                command=command,
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
            )
            response = ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                command=command,
                returncode=returncode,
                stdout=_truncate_stdout(stdout, tool_name),
                stderr=stderr[:10000],
                parsed=parsed_data,
                error=error_message
                + (" — partial output captured below" if timed_out and stdout else ""),
                timed_out=timed_out,
                duration_seconds=attempt_duration,
                alternative_tool_suggested=alternative_tool,
                recovery_info={
                    "attempts_made": attempt,
                    "recovery_applied": len(recovery_history) > 0,
                    "recovery_history": recovery_history,
                    "final_action": final_action,
                },
            )
            return response

        except Exception as exc:
            logger.exception("Docker exec failed for %s", tool_name)
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                command=command,
                error=str(exc),
            )
