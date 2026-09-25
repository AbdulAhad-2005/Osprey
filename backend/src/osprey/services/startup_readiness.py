"""Process readiness state for startup work that gates safe API operation."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from osprey.contract import API_CONTRACT_VERSION, APP_VERSION, CAPABILITIES


@dataclass(frozen=True)
class ReadinessState:
    ready: bool
    status: str
    error: str = ""


_lock = threading.Lock()
_state = ReadinessState(ready=False, status="starting")


def mark_starting() -> None:
    global _state
    with _lock:
        _state = ReadinessState(ready=False, status="starting")


def mark_ready() -> None:
    global _state
    with _lock:
        _state = ReadinessState(ready=True, status="ok")


def mark_failed(exc: BaseException) -> None:
    """Record a concise startup failure suitable for the local health API."""
    global _state
    detail = f"{type(exc).__name__}: {exc}".strip()[:500]
    with _lock:
        _state = ReadinessState(ready=False, status="not_ready", error=detail)


def snapshot(service: str) -> dict[str, Any]:
    with _lock:
        current = _state
    payload: dict[str, Any] = {
        "status": current.status,
        "service": service,
        "ready": current.ready,
        "version": APP_VERSION,
        "api_contract_version": API_CONTRACT_VERSION,
        "capabilities": list(CAPABILITIES),
    }
    if current.error:
        payload["error"] = current.error
    return payload
