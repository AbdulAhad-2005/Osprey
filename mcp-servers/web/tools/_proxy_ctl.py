"""Control mitmdump lifecycle for full-session passive traffic capture.

Not an MCP tool — underscore-prefixed. Wrapped by proxy_start.py/proxy_stop.py.
One mitmdump process per engagement, backgrounded (nohup+disown — the same
platform_shell session-persistence pattern documented in
skills/exploit/shell-management.md), tracked by a pidfile + a shared port
registry so concurrent engagements on the same container don't collide.

Actually verifies the listener bound (polls the port) before reporting
success — the exact check a previous, since-removed oast_callback tool
skipped, which is why it never reliably worked.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

_STATE_DIR = Path("/tmp/pentest_proxy")
_PORT_REGISTRY = _STATE_DIR / "ports.json"
_PORT_BASE = 28000
_PORT_MAX = 28999
_ADDON_CONTAINER = "/home/mcpuser/mcp-servers/_core/proxy_capture_addon.py"
_ADDON_FALLBACK = str(Path(__file__).resolve().parents[1] / "_core" / "proxy_capture_addon.py")


def _addon_path() -> str:
    return _ADDON_CONTAINER if os.path.exists(_ADDON_CONTAINER) else _ADDON_FALLBACK


def _pidfile(engagement_id: str) -> Path:
    return _STATE_DIR / f"{engagement_id}.pid"


def _flow_log(engagement_id: str) -> Path:
    return Path(f"/tmp/pentest/{engagement_id}/proxy_flows.jsonl")


def _read_registry() -> dict[str, int]:
    if not _PORT_REGISTRY.exists():
        return {}
    try:
        return json.loads(_PORT_REGISTRY.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _write_registry(reg: dict[str, int]) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    _PORT_REGISTRY.write_text(json.dumps(reg))


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", port))
            return False  # something answered — in use
        except (ConnectionRefusedError, socket.timeout, OSError):
            return True


def _port_listening(port: int) -> bool:
    return not _port_free(port)


def _allocate_port(engagement_id: str) -> int:
    reg = _read_registry()
    if engagement_id in reg and _port_free(reg[engagement_id]) is False:
        # Registered and something is actually there — trust it, the caller
        # will confirm liveness separately via the pidfile check.
        return reg[engagement_id]
    if engagement_id in reg:
        return reg[engagement_id]
    used = set(reg.values())
    for port in range(_PORT_BASE, _PORT_MAX + 1):
        if port in used:
            continue
        if _port_free(port):
            reg[engagement_id] = port
            _write_registry(reg)
            return port
    raise SystemExit("ERROR: no free proxy port in range 28000-28999")


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _ca_cert_path() -> str:
    home = os.environ.get("HOME", "/home/mcpuser")
    return f"{home}/.mitmproxy/mitmproxy-ca-cert.pem"


def status(engagement_id: str) -> dict:
    pidfile = _pidfile(engagement_id)
    reg = _read_registry()
    port = reg.get(engagement_id)
    if not pidfile.exists() or port is None:
        return {"status": "not_running", "engagement_id": engagement_id}
    try:
        pid = int(pidfile.read_text().strip())
    except (ValueError, OSError):
        return {"status": "not_running", "engagement_id": engagement_id}
    if not _pid_alive(pid) or not _port_listening(port):
        return {"status": "stale", "engagement_id": engagement_id, "port": port, "pid": pid}
    return {
        "status": "running",
        "engagement_id": engagement_id,
        "port": port,
        "pid": pid,
        "flow_log": str(_flow_log(engagement_id)),
        "ca_cert": _ca_cert_path(),
    }


def start(engagement_id: str) -> dict:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    current = status(engagement_id)
    if current["status"] == "running":
        return {**current, "already_running": True}

    port = _allocate_port(engagement_id)
    flow_log = _flow_log(engagement_id)
    flow_log.parent.mkdir(parents=True, exist_ok=True)
    pidfile = _pidfile(engagement_id)
    boot_log = _STATE_DIR / f"{engagement_id}.boot.log"

    cmd = [
        "mitmdump",
        "--listen-port", str(port),
        "-s", _addon_path(),
        "--set", f"flow_log={flow_log}",
        "--set", "termlog_verbosity=warn",
        "-q",
    ]
    with open(boot_log, "wb") as log_f:
        proc = subprocess.Popen(
            cmd,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,  # detach from this control process's session
        )
    pidfile.write_text(str(proc.pid))

    # Actually verify it bound before claiming success.
    for _ in range(25):  # ~5s
        if _port_listening(port):
            return {
                "status": "started",
                "engagement_id": engagement_id,
                "port": port,
                "pid": proc.pid,
                "flow_log": str(flow_log),
                "ca_cert": _ca_cert_path(),
            }
        time.sleep(0.2)

    boot_output = boot_log.read_text(errors="replace")[-1000:] if boot_log.exists() else ""
    return {
        "status": "error",
        "engagement_id": engagement_id,
        "error": "mitmdump did not bind the port within 5s",
        "boot_log_tail": boot_output,
    }


def stop(engagement_id: str) -> dict:
    pidfile = _pidfile(engagement_id)
    if not pidfile.exists():
        return {"status": "not_running", "engagement_id": engagement_id}
    try:
        pid = int(pidfile.read_text().strip())
        if _pid_alive(pid):
            os.kill(pid, signal.SIGTERM)
    except (ValueError, OSError):
        pass
    pidfile.unlink(missing_ok=True)
    reg = _read_registry()
    reg.pop(engagement_id, None)
    _write_registry(reg)
    return {"status": "stopped", "engagement_id": engagement_id}


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2 or argv[0] not in ("start", "stop", "status"):
        print("Usage: _proxy_ctl.py start|stop|status <engagement_id>", file=sys.stderr)
        raise SystemExit(2)
    action, engagement_id = argv[0], argv[1]
    result = {"start": start, "stop": stop, "status": status}[action](engagement_id)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
