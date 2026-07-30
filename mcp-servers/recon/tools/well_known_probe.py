"""well-known / policy-file probe — robots.txt, sitemap.xml, /.well-known/*.

Directly fetches the standard disclosure/policy files that reveal attack surface
and org intent: robots.txt Disallow entries (paths the target wants hidden),
sitemap URLs, security.txt contacts, and OIDC/SSO + app-association endpoints.
The sample engagement only found these incidentally in historical GAU data; a
direct probe confirms them live and extracts the disallowed paths as leads.
Low-touch: a handful of GETs to the target's own site.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "well_known_probe"
CATEGORY = "recon"

_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/change-password",
    "/.well-known/ai-plugin.json",
    "/humans.txt",
    "/crossdomain.xml",
]


def _base(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u.rstrip("/")


def build_command(**params: Any) -> str:
    url = _base(str(params.get("url") or params.get("target") or params.get("domain") or ""))
    timeout = int(params.get("timeout") or 12)
    if not url:
        raise ValueError("well_known_probe requires url=/domain=")
    lines = ["set +e", f'BASE="{url}"', f"TO={timeout}"]
    for p in _PATHS:
        lines.append(f'echo "=== PATH {p} ==="')
        # -sL follow redirects, -w capture final status; cap body to avoid huge sitemaps.
        lines.append(
            f'CODE=$(curl -sL -o /tmp/wk_body --max-time "$TO" -w "%{{http_code}}" "$BASE{p}" 2>/dev/null)'
        )
        lines.append('echo "STATUS: $CODE"')
        lines.append('if [ "$CODE" = "200" ]; then head -c 4000 /tmp/wk_body; echo; fi')
    lines.append('echo "=== DONE ==="')
    return "\n".join(lines)


def parse(result: ToolResult) -> dict[str, Any]:
    from _core.runner import default_parse
    return default_parse(result)


def run(
    url: str = "",
    domain: str = "",
    target: str = "",
    timeout: int = 12,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 90,
) -> dict[str, Any]:
    params = {"url": url or domain or target, "timeout": timeout}
    return run_tool(
        TOOL_NAME,
        build_command(**params),
        params=params,
        timeout=exec_timeout,
        use_cache=use_cache,
        use_recovery=use_recovery,
        parse_fn=parse,
    )
