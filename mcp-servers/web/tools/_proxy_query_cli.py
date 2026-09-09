"""List/filter or fetch full detail from a captured-traffic flow log.

Not an MCP tool — underscore-prefixed. Wrapped by proxy_flows.py (list) and
proxy_flow_detail.py (single flow, full headers+body both directions).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _proxy_flows_lib import get_flow, read_flows  # noqa: E402


def list_flows(
    engagement_id: str,
    host: str = "",
    method: str = "",
    contains: str = "",
    min_status: int = 0,
    limit: int = 100,
) -> dict:
    flows = read_flows(engagement_id)
    if host:
        flows = [f for f in flows if host.lower() in f.get("host", "").lower()]
    if method:
        flows = [f for f in flows if f.get("method", "").upper() == method.upper()]
    if contains:
        needle = contains.lower()
        flows = [f for f in flows if needle in f.get("url", "").lower()]
    if min_status:
        flows = [f for f in flows if f.get("status_code", 0) >= min_status]

    rows = [
        {
            "flow_id": f.get("flow_id"),
            "method": f.get("method"),
            "url": f.get("url"),
            "status_code": f.get("status_code"),
            "duration_ms": f.get("duration_ms"),
            "response_body_size": f.get("response_body_size"),
        }
        for f in flows[-limit:]
    ]
    return {"engagement_id": engagement_id, "total_captured": len(flows), "returned": len(rows), "flows": rows}


def flow_detail(engagement_id: str, flow_id: int) -> dict:
    flow = get_flow(engagement_id, flow_id)
    if flow is None:
        return {"error": f"flow_id {flow_id} not found for engagement {engagement_id}"}
    return flow


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="action", required=True)

    p_list = sub.add_parser("list")
    p_list.add_argument("engagement_id")
    p_list.add_argument("--host", default="")
    p_list.add_argument("--method", default="")
    p_list.add_argument("--contains", default="")
    p_list.add_argument("--min-status", type=int, default=0)
    p_list.add_argument("--limit", type=int, default=100)

    p_detail = sub.add_parser("detail")
    p_detail.add_argument("engagement_id")
    p_detail.add_argument("flow_id", type=int)

    args = ap.parse_args(argv)
    if args.action == "list":
        result = list_flows(
            args.engagement_id, args.host, args.method, args.contains, args.min_status, args.limit
        )
    else:
        result = flow_detail(args.engagement_id, args.flow_id)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
