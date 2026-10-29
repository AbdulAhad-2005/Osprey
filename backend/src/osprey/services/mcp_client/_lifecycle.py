"""MCPClient server lifecycle/status methods (mixin)."""

from __future__ import annotations
import asyncio
import json
import shutil
import time
from pathlib import Path
from typing import Any
from osprey.contract import APP_VERSION
from osprey.schemas.tools import (
    MCPServerCategory,
)
from osprey.services.mcp_client._helpers import (
    logger,
    _STDIO_LIMIT,
    _CORE_ENGINE_TOOLS,
    _kill_and_reap,
    MCPClientError,
)


class _LifecycleMixin:

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def _server_script(self, server: MCPServerCategory) -> Path:
        script = self._dir / server.value / "server.py"
        if not script.exists():
            raise FileNotFoundError(f"MCP server script not found: {script}")
        return script

    def _is_docker_available(self) -> bool:
        """True only when docker exists AND the Kali container is actually up.

        Falls back to native host execution when KALI_CONTAINER is unset, the
        docker CLI is missing, or the named container is not running — so a
        newcomer who ran `docker compose up` without the kali profile (or a
        Kali/native user with tools on the host) gets working tools instead of
        docker-exec errors.
        """
        if not self._use_docker:
            return False
        if shutil.which("docker") is None:
            return False
        return self._kali_container_running()

    def _kali_container_running(self) -> bool:
        import subprocess

        now = time.monotonic()
        if self._kali_running is not None and (now - self._kali_check_ts) < 30.0:
            return self._kali_running
        running = False
        try:
            result = subprocess.run(
                ["docker", "container", "inspect", "-f", "{{.State.Running}}", self._kali_container],
                capture_output=True,
                text=True,
                timeout=3,
            )
            running = result.returncode == 0 and result.stdout.strip() == "true"
        except Exception:
            running = False
        if running != self._kali_running:
            logger.info(
                "Kali container %s %s — %s execution",
                self._kali_container,
                "is running" if running else "not running",
                "docker" if running else "native/host",
            )
        self._kali_running = running
        self._kali_check_ts = now
        return running

    def execution_status(self) -> dict[str, Any]:
        """Report how (and whether) tools can actually run right now.

        Answers the exact question that made ``/scan --engine`` print N confusing
        per-tool ``(failed)`` lines: is there a working execution backend at all?
        Returns ``mode`` (docker/native), ``ready`` (bool), the container name,
        any missing core tools, and a human ``message`` with the fix.
        """
        def _missing_core() -> list[str]:
            return [t for t in _CORE_ENGINE_TOOLS if shutil.which(t) is None]

        if self._use_docker:
            if self._kali_container_running():
                return {
                    "mode": "docker",
                    "ready": True,
                    "degraded": False,
                    "container": self._kali_container,
                    "missing": [],
                    "message": f"Kali tools container '{self._kali_container}' is running.",
                }
            # Configured for docker but the container is down -> execution falls
            # back to running "natively" *inside the backend container*, which ships
            # no scanners and (being a container) cannot reach tools on the host.
            missing = _missing_core()
            present = [t for t in _CORE_ENGINE_TOOLS if t not in missing]
            if not missing:
                return {
                    "mode": "container-local",
                    "ready": True,
                    "degraded": False,
                    "container": self._kali_container,
                    "missing": [],
                    "message": (
                        f"Kali container '{self._kali_container}' is not running; core tools "
                        "are present in the backend image."
                    ),
                }
            if present:
                # Partial: a few tools happen to be in the backend image, but most
                # scanners are missing — the classic "lean docker, no Kali" trap
                # where scans come back almost empty. Flag it as degraded even
                # though *something* runs, so it never reads as a healthy setup.
                return {
                    "mode": "container-local",
                    "ready": True,
                    "degraded": True,
                    "container": self._kali_container,
                    "missing": missing,
                    "message": (
                        f"DEGRADED: Kali container '{self._kali_container}' is not running, so tools "
                        f"run inside the backend container — only {', '.join(present)} present; "
                        f"{', '.join(missing)} are MISSING, so most scans return nothing. A "
                        "containerized backend cannot use host tools. Fix: start the tools "
                        "container (docker compose --profile kali up -d), or run Osprey fully "
                        "local (README Path C) to use host tools."
                    ),
                }
            return {
                "mode": "container-local",
                "ready": False,
                "degraded": True,
                "container": self._kali_container,
                "missing": missing,
                "message": (
                    f"Kali tools container '{self._kali_container}' is not running and the backend "
                    f"container has no scanners ({', '.join(missing)}). Every compiled tool will "
                    "fail. A containerized backend cannot reach host tools. Fix: start the tools "
                    "container (docker compose --profile kali up -d), or run Osprey fully local "
                    "(README Path C)."
                ),
            }

        # Native mode explicitly requested (KALI_CONTAINER unset/empty) — this one
        # really is host execution, so host PATH is the source of truth.
        missing = _missing_core()
        present = [t for t in _CORE_ENGINE_TOOLS if t not in missing]
        ready = bool(present)
        return {
            "mode": "native",
            "ready": ready,
            "degraded": ready and bool(missing),
            "container": "",
            "missing": missing,
            "message": (
                "Native host execution."
                + (f" Missing core tools on PATH: {', '.join(missing)} — install them for full coverage." if missing else " Core tools present.")
                if ready
                else (
                    f"Native host execution but no core scanners on PATH ({', '.join(missing)}). "
                    "Install them (see README Path C) or run the kali-tools container."
                )
            ),
        }

    async def ensure_server(self, server: MCPServerCategory) -> asyncio.subprocess.Process:
        """Start the server if not already running, return the process."""
        async with self._lock:
            proc = self._processes.get(server)
            if proc is not None and proc.returncode is None:
                return proc

            if self._use_docker and self._is_docker_available():
                proc = await self._start_in_docker(server)
            else:
                proc = await self._start_local(server)

            try:
                await self._initialize_session(proc)
            except Exception:
                await _kill_and_reap(proc)
                raise

            self._processes[server] = proc
            logger.info("MCP server %s started (pid=%d)", server.value, proc.pid)
            return proc

    async def _initialize_session(self, proc: asyncio.subprocess.Process) -> None:
        """Perform the mandatory MCP ``initialize`` handshake before any
        ``tools/call``. This client speaks raw JSON-RPC over stdio instead of
        the SDK's ``ClientSession``, so without this the server-side session
        never leaves ``NotInitialized`` state and rejects every subsequent
        request with ``-32602 Invalid request parameters`` — the SDK enforces
        this at the protocol level (``mcp/server/session.py``), it isn't
        optional just because our own client hand-builds the JSON-RPC frames.
        """
        from mcp.types import LATEST_PROTOCOL_VERSION

        init_request = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "osprey-backend",
                    "version": APP_VERSION,
                },
            },
        }
        raw = await self._send_and_receive(proc, init_request, timeout=15)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise MCPClientError(
                f"MCP initialize handshake got a non-JSON response: {raw[:300]!r}"
            ) from exc
        if "error" in data:
            raise MCPClientError(f"MCP initialize handshake failed: {data['error']}")

        # notifications/initialized — a notification (no "id"), no response sent.
        assert proc.stdin is not None
        notify = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        proc.stdin.write((json.dumps(notify) + "\n").encode())
        await proc.stdin.drain()

    async def _start_in_docker(self, server: MCPServerCategory) -> asyncio.subprocess.Process:
        """Start MCP server inside the kali-tools container via docker exec."""
        script = f"/home/mcpuser/mcp-servers/{server.value}/server.py"
        logger.info("Starting MCP server in docker: %s", self._kali_container)

        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", "-i", self._kali_container,
            "python3", script,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_STDIO_LIMIT,
        )
        return proc

    async def _start_local(self, server: MCPServerCategory) -> asyncio.subprocess.Process:
        """Start MCP server as a local subprocess."""
        script = self._server_script(server)
        logger.info("Starting local MCP server: %s", script)

        proc = await asyncio.create_subprocess_exec(
            "python3", str(script),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_STDIO_LIMIT,
        )
        return proc

    async def stop_server(self, server: MCPServerCategory) -> None:
        proc = self._processes.pop(server, None)
        if proc is not None and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                proc.kill()
            logger.info("MCP server %s stopped", server.value)

    async def stop_all(self) -> None:
        for server in list(self._processes):
            await self.stop_server(server)
