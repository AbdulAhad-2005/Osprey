"""mitmproxy addon: log every completed flow to a JSON-lines file.

Loaded via `mitmdump -s proxy_capture_addon.py --set flow_log=<path>`. Not an
MCP tool — invoked only as a mitmproxy addon by mcp-servers/web/tools/
_proxy_ctl.py's `start` action.

One line per flow: method, host, path, query, status, timing, request/response
headers, and a size-capped text body (binary/media responses are recorded by
content-type and size only — capturing a video byte-for-byte in a JSON log is
pointless bloat, not a passive-capture feature). flow_id is a monotonically
increasing counter seeded from the existing log's line count, so ids stay
stable across a mitmdump restart on the same engagement instead of resetting
to 0 and colliding with earlier flows still referenced by proxy_replay.
"""

from __future__ import annotations

import json
import os
import threading
import time

from mitmproxy import http

_BODY_CAP = 8000
_TEXTUAL_TYPES = ("text/", "application/json", "application/xml", "application/x-www-form-urlencoded")


class FlowLogger:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._path = ""
        self._counter = 0

    def load(self, flow_log: str) -> None:
        self._path = flow_log
        os.makedirs(os.path.dirname(flow_log) or ".", exist_ok=True)
        if os.path.exists(flow_log):
            with open(flow_log, "r", encoding="utf-8", errors="replace") as f:
                self._counter = sum(1 for _ in f)

    def _is_textual(self, content_type: str) -> bool:
        return any(content_type.startswith(t) for t in _TEXTUAL_TYPES)

    def _body(self, data: bytes | None, content_type: str) -> tuple[str, int]:
        if not data:
            return "", 0
        size = len(data)
        if not self._is_textual(content_type):
            return f"<{size} bytes, {content_type or 'unknown type'} — not captured>", size
        text = data.decode("utf-8", errors="replace")
        return (text[:_BODY_CAP] + ("...<truncated>" if len(text) > _BODY_CAP else "")), size

    def log(self, flow: "http.HTTPFlow") -> None:
        if not self._path:
            return
        req = flow.request
        resp = flow.response
        req_ct = req.headers.get("content-type", "")
        resp_ct = resp.headers.get("content-type", "") if resp else ""
        req_body, req_size = self._body(req.raw_content, req_ct)
        resp_body, resp_size = self._body(resp.raw_content if resp else None, resp_ct)

        with self._lock:
            flow_id = self._counter
            self._counter += 1
            row = {
                "flow_id": flow_id,
                "timestamp": time.time(),
                "method": req.method,
                "scheme": req.scheme,
                "host": req.host,
                "port": req.port,
                "path": req.path,
                "url": req.pretty_url,
                "request_headers": dict(req.headers),
                "request_body": req_body,
                "request_body_size": req_size,
                "status_code": resp.status_code if resp else 0,
                "response_headers": dict(resp.headers) if resp else {},
                "response_body": resp_body,
                "response_body_size": resp_size,
                "duration_ms": int(((resp.timestamp_end or time.time()) - req.timestamp_start) * 1000)
                if resp
                else 0,
            }
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")

    def response(self, flow: "http.HTTPFlow") -> None:
        self.log(flow)


addons = [FlowLogger()]


def load(loader) -> None:  # noqa: ANN001 — mitmproxy addon hook signature
    loader.add_option("flow_log", str, "", "Path to append captured flows as JSON lines")


def configure(updated) -> None:  # noqa: ANN001 — mitmproxy addon hook signature
    from mitmproxy import ctx

    if "flow_log" in updated:
        addons[0].load(ctx.options.flow_log)
