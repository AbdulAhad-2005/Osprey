"""Shared Shodan REST helpers (not an MCP tool — underscore-prefixed)."""

from __future__ import annotations

import json
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def _api_key() -> str:
    key = (os.environ.get("SHODAN_API_KEY") or "").strip()
    if not key:
        raise SystemExit(
            "ERROR: SHODAN_API_KEY is not set. Add it to .env and restart kali-tools/backend."
        )
    return key


def _get(url: str, params: dict[str, Any], timeout: int = 45) -> Any:
    qs = urlencode(params)
    req = Request(f"{url}?{qs}", headers={"User-Agent": "pentest-platform-shodan/1.0"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"ERROR: Shodan HTTP {exc.code}: {body}") from exc
    except URLError as exc:
        raise SystemExit(f"ERROR: Shodan network failure: {exc}") from exc


def search(query: str, limit: int = 20) -> dict[str, Any]:
    key = _api_key()
    limit = max(1, min(int(limit), 100))
    data = _get(
        "https://api.shodan.io/shodan/host/search",
        {"key": key, "query": query},
    )
    matches = data.get("matches") or []
    total = data.get("total", len(matches))
    rows = []
    for item in matches[:limit]:
        loc = item.get("location") or {}
        rows.append(
            {
                "ip": item.get("ip_str") or "",
                "port": item.get("port"),
                "org": item.get("org") or "",
                "hostnames": item.get("hostnames") or [],
                "domains": item.get("domains") or [],
                "product": item.get("product") or "",
                "transport": item.get("transport") or "tcp",
                "country": loc.get("country_name") or "",
                "banner": (item.get("data") or "")[:300],
            }
        )
    return {"action": "search", "query": query, "total": total, "returned": len(rows), "matches": rows}


def host_info(ip: str) -> dict[str, Any]:
    key = _api_key()
    data = _get(f"https://api.shodan.io/shodan/host/{ip}", {"key": key})
    return {
        "action": "host",
        "ip": data.get("ip_str") or ip,
        "org": data.get("org") or "",
        "isp": data.get("isp") or "",
        "os": data.get("os") or "",
        "hostnames": data.get("hostnames") or [],
        "domains": data.get("domains") or [],
        "ports": data.get("ports") or [],
        "vulns": list(data.get("vulns") or []),
        "last_update": data.get("last_update") or "",
        "country": data.get("country_name") or "",
        "city": data.get("city") or "",
        "data_count": len(data.get("data") or []),
    }


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "Usage: _shodan_cli.py search <query> [limit]\n"
            "       _shodan_cli.py host <ip>",
            file=sys.stderr,
        )
        raise SystemExit(2)

    action = argv[0].strip().lower()
    if action == "search":
        if len(argv) < 2:
            raise SystemExit("ERROR: search requires a query")
        query = argv[1]
        limit = int(argv[2]) if len(argv) > 2 else 20
        print(json.dumps(search(query, limit), indent=2))
        return
    if action == "host":
        if len(argv) < 2:
            raise SystemExit("ERROR: host requires an IP")
        print(json.dumps(host_info(argv[1]), indent=2))
        return
    raise SystemExit(f"ERROR: unknown action {action!r} (use search|host)")


if __name__ == "__main__":
    main()
