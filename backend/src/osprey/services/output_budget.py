"""Single source of truth for how much raw tool stdout reaches a driver.

Every place that used to invent its own truncation constant (the MCP/CLI
formatter, the backend's self-driving agent, the CLI's own loop) calls
``stdout_budget()``/``truncate_stdout()`` here instead. One tool-aware policy,
tunable via ``config/output_budget.yaml`` without a code change.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from osprey.services.config_loader import read_config

_DEFAULTS: dict[str, Any] = {
    "default_chars": 20_000,
    "high_value_chars": 200_000,
    "high_value_tools": [],
    "high_value_prefixes": ["shell:", "script:"],
    "head_fraction": 0.72,
    "tail_fraction": 0.28,
    "history_cap_chars": 3_000,
}

_TRIM_MARKER = "\n\n…[trimmed — full stdout on Kali{path} — platform_artifact]…\n\n"


@lru_cache(maxsize=1)
def load_output_budget() -> dict[str, Any]:
    data = dict(_DEFAULTS)
    raw = read_config("output_budget.yaml")
    if isinstance(raw, dict):
        data.update(raw)
    data["default_chars"] = max(1000, int(data.get("default_chars") or 20_000))
    data["high_value_chars"] = max(
        data["default_chars"], int(data.get("high_value_chars") or 200_000)
    )
    tools = data.get("high_value_tools") or []
    data["high_value_tools"] = frozenset(str(t).strip() for t in tools if str(t).strip())
    prefixes = data.get("high_value_prefixes") or []
    data["high_value_prefixes"] = tuple(str(p) for p in prefixes if str(p))
    head = float(data.get("head_fraction") or 0.72)
    tail = float(data.get("tail_fraction") or 0.28)
    total = head + tail
    data["head_fraction"] = head / total if total > 0 else 0.72
    data["tail_fraction"] = tail / total if total > 0 else 0.28
    data["history_cap_chars"] = max(500, int(data.get("history_cap_chars") or 3_000))
    return data


def reload_output_budget() -> dict[str, Any]:
    load_output_budget.cache_clear()
    return load_output_budget()


def is_high_value(tool_name: str) -> bool:
    name = (tool_name or "").strip()
    cfg = load_output_budget()
    if name in cfg["high_value_tools"]:
        return True
    return any(name.startswith(p) for p in cfg["high_value_prefixes"])


def stdout_budget(tool_name: str) -> int:
    """Chars of raw stdout to surface to a driver for this tool."""
    cfg = load_output_budget()
    return int(cfg["high_value_chars"] if is_high_value(tool_name) else cfg["default_chars"])


def history_result_cap() -> int:
    """Chars of a past tool result worth re-sending every future turn.

    A distinct, smaller number than ``stdout_budget`` — that answers "how much
    to show right now", this answers "how much of an old turn is worth paying
    for again on every later turn." Only meant for token-budget-constrained
    callers (see ``cli/agent/loop.py``); an unconstrained caller keeps the
    already-budgeted server result in full.
    """
    return int(load_output_budget()["history_cap_chars"])


def truncate_stdout(tool_name: str, stdout: str, *, artifact_path: str = "") -> str:
    """Head+tail trim ``stdout`` to this tool's budget, with an artifact pointer.

    Returns ``stdout`` unchanged when it already fits the budget.
    """
    if not stdout:
        return stdout
    budget = stdout_budget(tool_name)
    if len(stdout) <= budget:
        return stdout
    cfg = load_output_budget()
    marker = _TRIM_MARKER.format(path=f" `{artifact_path}`" if artifact_path else "")
    # Reserve room for the marker itself so the total stays near-budget.
    remaining = max(budget - len(marker), 200)
    head_cap = max(int(remaining * cfg["head_fraction"]), 100)
    tail_cap = max(remaining - head_cap, 100)
    return stdout[:head_cap] + marker + stdout[-tail_cap:]
