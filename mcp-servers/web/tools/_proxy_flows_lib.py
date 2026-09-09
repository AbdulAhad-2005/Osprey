"""Shared JSONL flow-log reader for proxy_flows/proxy_flow_detail/proxy_replay.

Not an MCP tool — underscore-prefixed. The log format is written by
mcp-servers/_core/proxy_capture_addon.py (one JSON object per line, in
flow_id order since mitmdump appends as flows complete).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def flow_log_path(engagement_id: str) -> Path:
    return Path(f"/tmp/pentest/{engagement_id}/proxy_flows.jsonl")


def read_flows(engagement_id: str) -> list[dict[str, Any]]:
    path = flow_log_path(engagement_id)
    if not path.exists():
        return []
    flows = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                flows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return flows


def get_flow(engagement_id: str, flow_id: int) -> dict[str, Any] | None:
    for flow in read_flows(engagement_id):
        if flow.get("flow_id") == flow_id:
            return flow
    return None
