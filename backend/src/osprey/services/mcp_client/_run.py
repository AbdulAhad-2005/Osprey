"""MCPClient argv/script execution + stdio round-trip methods (mixin)."""

from __future__ import annotations
import asyncio
import json
import time
from typing import Any
from osprey.schemas.tools import (
    ToolExecutionResponse,
)
from osprey.services.mcp_client._helpers import (
    logger,
    _KALI_EXEC_PATH,
    _truncate_stdout,
    _kill_and_reap,
    _drain_partial,
)


class _RunMixin:

    async def run_argv(
        self,
        argv: list[str],
        *,
        timeout: int = 180,
        tool_name: str = "shell",
    ) -> ToolExecutionResponse:
        """Run a pre-validated argv list inside Kali (no shell metacharacters)."""
        if not argv:
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                error="empty argv",
            )
        # Native mode (no KALI_CONTAINER / no docker): run the already-validated
        # argv directly on the host. The caller (shell_exec) has run the same
        # allowlist + metacharacter checks it applies before docker exec, so this
        # is not a new trust boundary — it just targets the host's own tools.
        if not self._use_docker or not self._is_docker_available():
            return await self._run_argv_local(argv, timeout=timeout, tool_name=tool_name)

        printable = " ".join(argv)
        logger.info("Shell argv in kali-tools: %s", printable)
        started = time.monotonic()
        try:
            # -e PATH so a bare (non-login) docker exec still resolves ~/.local/bin
            # and pipx tools, matching the tool/script execution paths.
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "exec",
                "-i",
                "-e",
                f"PATH={_KALI_EXEC_PATH}",
                self._kali_container,
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
            stdout = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
            returncode = proc.returncode
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=returncode == 0,
                command=printable,
                returncode=returncode,
                stdout=_truncate_stdout(stdout, tool_name),
                stderr=stderr[:10000],
                duration_seconds=time.monotonic() - started,
            )
        except asyncio.TimeoutError:
            partial_stdout, partial_stderr = await _drain_partial(proc)
            await _kill_and_reap(proc)
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                command=printable,
                stdout=_truncate_stdout(partial_stdout, tool_name),
                stderr=partial_stderr[:10000],
                error=f"Execution timed out after {timeout}s"
                + (" — partial output captured below" if partial_stdout else ""),
                timed_out=True,
                duration_seconds=time.monotonic() - started,
            )
        except Exception as exc:
            logger.exception("Shell argv failed for %s", tool_name)
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                command=printable,
                error=str(exc),
            )

    async def run_script_file(
        self,
        *,
        code: bytes,
        remote_path: str,
        interpreter: str,
        workdir: str,
        timeout: int = 300,
        tool_name: str = "script",
        artifact_prefix: str = "",
    ) -> ToolExecutionResponse:
        """Write ``code`` into Kali at ``remote_path``, then run ``interpreter path``.

        Full stdout/stderr are also saved under ``workdir`` so truncation in the
        API response does not lose evidence.
        """
        if not self._use_docker or not self._is_docker_available():
            return await self._run_script_local(
                code=code,
                remote_path=remote_path,
                interpreter=interpreter,
                workdir=workdir,
                timeout=timeout,
                tool_name=tool_name,
                artifact_prefix=artifact_prefix,
            )

        printable = f"{interpreter} {remote_path}"
        prefix = artifact_prefix or "out"
        stdout_path = f"{workdir}/{prefix}.stdout.txt"
        stderr_path = f"{workdir}/{prefix}.stderr.txt"
        # Track every subprocess spawned so a timeout on ANY step (mkdir/tee/
        # chmod/the script itself) still reaps whichever one was in flight —
        # a single `proc` var isn't bound until the last step is reached.
        spawned: list[asyncio.subprocess.Process] = []
        started = time.monotonic()
        try:
            mkdir = await asyncio.create_subprocess_exec(
                "docker",
                "exec",
                self._kali_container,
                "mkdir",
                "-p",
                workdir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            spawned.append(mkdir)
            await asyncio.wait_for(mkdir.communicate(), timeout=30)

            tee = await asyncio.create_subprocess_exec(
                "docker",
                "exec",
                "-i",
                self._kali_container,
                "tee",
                remote_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            spawned.append(tee)
            tee_out, tee_err = await asyncio.wait_for(
                tee.communicate(input=code),
                timeout=60,
            )
            if tee.returncode != 0:
                return ToolExecutionResponse(
                    tool_name=tool_name,
                    success=False,
                    command=f"tee {remote_path}",
                    error=(tee_err or tee_out or b"tee failed").decode(errors="replace")[:2000],
                )

            if interpreter in ("bash", "sh"):
                chmod = await asyncio.create_subprocess_exec(
                    "docker",
                    "exec",
                    self._kali_container,
                    "chmod",
                    "+x",
                    remote_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                spawned.append(chmod)
                await asyncio.wait_for(chmod.communicate(), timeout=15)

            # Run via bash so we can tee full output to workspace files.
            if interpreter == "python3":
                inner = f"{interpreter} -u {remote_path}"
            else:
                inner = f"{interpreter} {remote_path}"
            wrapped = (
                f"set -o pipefail; {inner} > {stdout_path} 2> {stderr_path}; "
                f"ec=$?; "
                f"echo __PENTEST_STDOUT_PATH__={stdout_path}; "
                f"echo __PENTEST_STDERR_PATH__={stderr_path}; "
                f"echo __PENTEST_EXIT__=$ec; "
                f"wc -c < {stdout_path} | awk '{{print \"__PENTEST_STDOUT_BYTES__=\" $1}}'; "
                f"head -c 280000 {stdout_path}; "
                f"exit $ec"
            )
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "exec",
                "-i",
                self._kali_container,
                "bash",
                "-lc",
                wrapped,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            spawned.append(proc)
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
            raw_out = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
            raw_err = stderr_bytes.decode(errors="replace") if stderr_bytes else ""

            # Strip meta markers from the preview returned to the LLM
            preview_lines = []
            meta: dict[str, str] = {
                "stdout_path": stdout_path,
                "stderr_path": stderr_path,
            }
            for line in raw_out.splitlines():
                if line.startswith("__PENTEST_STDOUT_PATH__="):
                    meta["stdout_path"] = line.split("=", 1)[1]
                elif line.startswith("__PENTEST_STDERR_PATH__="):
                    meta["stderr_path"] = line.split("=", 1)[1]
                elif line.startswith("__PENTEST_EXIT__="):
                    meta["exit"] = line.split("=", 1)[1]
                elif line.startswith("__PENTEST_STDOUT_BYTES__="):
                    meta["stdout_bytes"] = line.split("=", 1)[1]
                else:
                    preview_lines.append(line)
            preview = "\n".join(preview_lines)
            if meta.get("stdout_bytes"):
                try:
                    nbytes = int(meta["stdout_bytes"])
                except ValueError:
                    nbytes = 0
                if nbytes > 280000:
                    preview += (
                        f"\n\n[truncated preview — full stdout at {meta['stdout_path']} "
                        f"({nbytes} bytes). Re-read with a small script that prints "
                        f"head/tail/counts from that file.]"
                    )

            return ToolExecutionResponse(
                tool_name=tool_name,
                success=proc.returncode == 0,
                command=printable,
                returncode=proc.returncode,
                stdout=preview[:280000],
                stderr=raw_err[:40000],
                duration_seconds=time.monotonic() - started,
                parsed={"artifacts": meta},
                hybrid={
                    "artifacts": meta,
                    "note": "Full script output saved under engagement workspace in Kali.",
                },
            )
        except asyncio.TimeoutError:
            # The script's own stdout/stderr are redirected INTO the container at
            # stdout_path/stderr_path as they're produced (see `wrapped` above) —
            # that file already holds whatever the script printed before the
            # timeout, even though the wrapper's own pipe (drained below, usually
            # empty here since the wrapper only echoes its meta markers at the
            # very end) never got that far. Surface the paths so the caller can
            # still read partial results via platform_artifact instead of nothing.
            partial_stdout, partial_stderr = await _drain_partial(spawned[-1] if spawned else None)
            for p in spawned:
                await _kill_and_reap(p)
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                command=printable,
                stdout=_truncate_stdout(partial_stdout, tool_name),
                stderr=partial_stderr[:10000],
                error=f"Script timed out after {timeout}s",
                timed_out=True,
                duration_seconds=time.monotonic() - started,
                hybrid={
                    "artifacts": {"stdout_path": stdout_path, "stderr_path": stderr_path},
                    "note": (
                        "Script output streams to these paths in Kali as it runs — "
                        "read them with platform_artifact for whatever printed before "
                        "the timeout, even though this response's stdout is empty/partial."
                    ),
                },
            )
        except Exception as exc:
            logger.exception("Script exec failed for %s", tool_name)
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                command=printable,
                error=str(exc),
            )

    async def _run_argv_local(
        self, argv: list[str], *, timeout: int, tool_name: str
    ) -> ToolExecutionResponse:
        """Native-mode host execution of a pre-validated argv (no docker exec)."""
        printable = " ".join(argv)
        logger.info("Shell argv on host (native mode): %s", printable)
        proc: asyncio.subprocess.Process | None = None
        started = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            stdout = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=proc.returncode == 0,
                command=printable,
                returncode=proc.returncode,
                stdout=_truncate_stdout(stdout, tool_name),
                stderr=stderr[:10000],
                duration_seconds=time.monotonic() - started,
            )
        except FileNotFoundError as exc:
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                command=printable,
                error=(
                    f"'{argv[0]}' not found on the host PATH. In native mode tools run "
                    f"on this machine — install it, or run the kali-tools container. ({exc})"
                ),
            )
        except asyncio.TimeoutError:
            partial_stdout, partial_stderr = await _drain_partial(proc)
            await _kill_and_reap(proc)
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                command=printable,
                stdout=_truncate_stdout(partial_stdout, tool_name),
                stderr=partial_stderr[:10000],
                error=f"Execution timed out after {timeout}s"
                + (" — partial output captured below" if partial_stdout else ""),
                timed_out=True,
                duration_seconds=time.monotonic() - started,
            )
        except Exception as exc:
            logger.exception("Native shell argv failed for %s", tool_name)
            return ToolExecutionResponse(
                tool_name=tool_name, success=False, command=printable, error=str(exc)
            )

    async def _run_script_local(
        self,
        *,
        code: bytes,
        remote_path: str,
        interpreter: str,
        workdir: str,
        timeout: int,
        tool_name: str,
        artifact_prefix: str,
    ) -> ToolExecutionResponse:
        """Native-mode host execution of a write→run script (no docker/Kali).

        Container-style workspace paths (``/home/mcpuser/...``, ``/tmp/...``) do
        not exist on an arbitrary host, so the script and its full stdout/stderr
        are written under the OS temp dir instead; the returned artifact paths
        point there for follow-up reads.
        """
        import shutil as _shutil
        import tempfile as _tempfile
        from pathlib import Path as _Path

        # python3 may be exposed as `python` on some hosts (notably Windows).
        if interpreter == "python3" and _shutil.which("python3") is None and _shutil.which("python"):
            interpreter = "python"

        prefix = artifact_prefix or "run"
        local_workdir = _Path(_tempfile.gettempdir()) / "pentest-native" / prefix
        local_workdir.mkdir(parents=True, exist_ok=True)
        script_path = local_workdir / _Path(remote_path).name
        stdout_path = local_workdir / f"{prefix}.stdout.txt"
        stderr_path = local_workdir / f"{prefix}.stderr.txt"
        script_path.write_bytes(code)

        printable = f"{interpreter} {script_path}"
        logger.info("Script on host (native mode): %s", printable)
        proc: asyncio.subprocess.Process | None = None
        started = time.monotonic()
        try:
            argv = [interpreter] + (["-u"] if interpreter == "python" else []) + [str(script_path)]
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            stdout = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
            stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
            stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
            meta = {"stdout_path": str(stdout_path), "stderr_path": str(stderr_path)}
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=proc.returncode == 0,
                command=printable,
                returncode=proc.returncode,
                stdout=stdout[:280000],
                stderr=stderr[:40000],
                duration_seconds=time.monotonic() - started,
                parsed={"artifacts": meta},
                hybrid={"artifacts": meta, "note": "Native mode — script output saved on host temp dir."},
            )
        except FileNotFoundError as exc:
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                command=printable,
                error=f"Interpreter '{interpreter}' not found on host PATH. ({exc})",
            )
        except asyncio.TimeoutError:
            partial_stdout, partial_stderr = await _drain_partial(proc)
            await _kill_and_reap(proc)
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                command=printable,
                stdout=_truncate_stdout(partial_stdout, tool_name),
                stderr=partial_stderr[:10000],
                error=f"Script timed out after {timeout}s",
                timed_out=True,
                duration_seconds=time.monotonic() - started,
                hybrid={"artifacts": {"stdout_path": str(stdout_path), "stderr_path": str(stderr_path)}},
            )
        except Exception as exc:
            logger.exception("Native script exec failed for %s", tool_name)
            return ToolExecutionResponse(
                tool_name=tool_name, success=False, command=printable, error=str(exc)
            )

    async def _send_and_receive(
        self,
        proc: asyncio.subprocess.Process,
        request: dict[str, Any],
        timeout: int,
    ) -> bytes:
        """Send a JSON-RPC request and read the response."""
        assert proc.stdin is not None
        assert proc.stdout is not None

        payload = json.dumps(request) + "\n"
        proc.stdin.write(payload.encode())
        await proc.stdin.drain()

        response_line = await asyncio.wait_for(
            proc.stdout.readline(),
            timeout=timeout,
        )
        return response_line

    def _parse_response(
        self,
        tool_name: str,
        raw: bytes,
    ) -> ToolExecutionResponse:
        """Parse a JSON-RPC response into a ToolExecutionResponse."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                error=f"Invalid JSON response from MCP server: {raw[:500]!r}",
            )

        if "error" in data:
            err = data["error"]
            return ToolExecutionResponse(
                tool_name=tool_name,
                success=False,
                error=err.get("message", str(err)),
            )

        result = data.get("result", {})
        content = result.get("content", [])
        stdout_text = ""
        stderr_text = ""
        for block in content:
            if block.get("type") == "text":
                stdout_text += block.get("text", "")
            elif block.get("type") == "error":
                stderr_text += block.get("text", "")

        returncode = result.get("returncode")

        parsed_data: dict[str, Any] = {}
        try:
            maybe_json = json.loads(stdout_text)
            if isinstance(maybe_json, dict) and "parsed" in maybe_json:
                p = maybe_json.get("parsed")
                if p and isinstance(p, dict):
                    parsed_data = p
        except (json.JSONDecodeError, TypeError):
            pass

        return ToolExecutionResponse(
            tool_name=tool_name,
            success=returncode == 0 if returncode is not None else bool(stdout_text),
            stdout=stdout_text,
            stderr=stderr_text,
            returncode=returncode,
            parsed=parsed_data,
        )
