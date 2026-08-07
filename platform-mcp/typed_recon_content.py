"""Typed FastMCP tools for active recon: content discovery, parameter discovery,
crawling, JavaScript analysis, and policy/email-posture probing.

These call the same backend execute path as platform_exec but give the Commander
explicit parameters (url / mode / wordlist / depth …) so it does not have to
hand-build params_json. All are RECON-phase capabilities — mapping the live
attack surface (paths, hidden params, JS endpoints/secrets, cloud refs) that
subdomain/port enumeration alone never reaches.
"""

from __future__ import annotations

from typing import Any, Callable

TYPED_RECON_CONTENT_TOOLS: tuple[str, ...] = (
    "feroxbuster_scan",
    "ffuf_scan",
    "gobuster_scan",
    "arjun_scan",
    "x8_parameter_discovery",
    "katana_crawl",
    "js_recon",
    "email_security_probe",
    "well_known_probe",
)

_TOOL_BLURBS: dict[str, str] = {
    "feroxbuster_scan": (
        "Recursive content/directory discovery (url=). Default fast content-discovery tool; "
        "NDJSON hits with status/size. Tune depth=, wordlist=, or -x php,txt via additional_args."
    ),
    "ffuf_scan": (
        "Fast fuzzing (url=, mode=directory|vhost|parameter). directory=paths, vhost=Host-header "
        "virtual hosts (great when many names share one IP), parameter=hidden query params."
    ),
    "gobuster_scan": "Directory/DNS/vhost brute force (url=, mode=dir|dns|vhost). Alternative to feroxbuster.",
    "arjun_scan": "Active HTTP parameter discovery on a live endpoint (url=, method=GET/POST). Finds hidden params.",
    "x8_parameter_discovery": (
        "Hidden parameter brute-force via x8 (url=, method=). Detects params by response-diff — a "
        "different method from arjun; run it as a second pass when arjun looks thin. Bundled param "
        "wordlist by default; pass wordlist= for a bigger set."
    ),
    "katana_crawl": (
        "JS-aware crawler (url=) — follows links + parses JavaScript for endpoints; also mines URL params. "
        "For SPA / JS-rendered apps (React/Vue/Angular) add additional_args=\"-headless -xhr -no-sandbox\" to "
        "render the DOM in real Chromium and capture client-side routes + XHR/fetch API calls that static crawling misses. "
        "For deeper interaction (login, forms, business logic) use browser_scrape / browser_flow instead."
    ),
    "js_recon": (
        "Analyze a page's JavaScript (target= page/JS URL): extract endpoints/API paths, hardcoded "
        "secrets (API keys, tokens, JWTs, private keys) and exposed cloud storage. Key for SPA/API targets."
    ),
    "email_security_probe": "Email anti-spoofing posture (domain=): SPF / DKIM / DMARC / MX. Flags missing SPF/DMARC.",
    "well_known_probe": (
        "Fetch robots.txt / sitemap.xml / .well-known/* (url=/domain=) and surface Disallow paths, "
        "sitemap URLs, security.txt and OIDC/SSO endpoints as attack-surface leads."
    ),
}


# Per-tool default foreground timeouts (seconds). These tools routinely run
# past a flat 300s on real targets (recursive content discovery, JS fetch,
# active param probing), forcing needless background re-runs. 0 from the caller
# means "use this default"; an explicit value still overrides.
_CONTENT_TIMEOUTS: dict[str, int] = {
    "feroxbuster_scan": 600,
    "ffuf_scan": 600,
    "gobuster_scan": 600,
    "arjun_scan": 600,
    "katana_crawl": 600,
    "js_recon": 480,
    "email_security_probe": 120,
    "well_known_probe": 120,
}
_DEFAULT_CONTENT_TIMEOUT = 300


def _build_params(
    *,
    url: str = "",
    target: str = "",
    domain: str = "",
    mode: str = "",
    wordlist: str = "",
    method: str = "",
    depth: str = "",
    max_files: str = "",
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for key, val in (
        ("url", url),
        ("target", target),
        ("domain", domain),
        ("mode", mode),
        ("wordlist", wordlist),
        ("method", method),
        ("depth", depth),
        ("max_files", max_files),
    ):
        if str(val).strip():
            params[key] = str(val).strip()
    return params


def register_typed_recon_content_tools(mcp: Any, *, execute: Callable[..., str]) -> int:
    """Register one FastMCP tool per active-recon catalog name."""
    count = 0
    for tool_name in TYPED_RECON_CONTENT_TOOLS:
        blurb = _TOOL_BLURBS.get(tool_name, f"Recon tool {tool_name}.")

        def _make(name: str, doc: str) -> Callable[..., str]:
            def _tool(
                url: str = "",
                target: str = "",
                domain: str = "",
                mode: str = "",
                wordlist: str = "",
                method: str = "",
                depth: str = "",
                max_files: str = "",
                additional_args: str = "",
                timeout_seconds: int = 0,
                engagement_id: str = "",
            ) -> str:
                params = _build_params(
                    url=url, target=target, domain=domain, mode=mode,
                    wordlist=wordlist, method=method, depth=depth, max_files=max_files,
                )
                effective_timeout = timeout_seconds or _CONTENT_TIMEOUTS.get(
                    name, _DEFAULT_CONTENT_TIMEOUT
                )
                return execute(
                    name,
                    params,
                    additional_args=(additional_args or "").strip(),
                    timeout_seconds=effective_timeout,
                    engagement_id=engagement_id,
                )

            _tool.__name__ = name
            _tool.__doc__ = (
                f"{doc}\n\n"
                "RECON attack-surface mapping. Typed tool; prefer over platform_exec JSON. "
                "Aliases url|target|domain accepted. engagement_id= pins this call to a specific "
                "engagement (from platform_set_target). Escape hatch: platform_shell / platform_script."
            )
            return _tool

        handler = _make(tool_name, blurb)
        mcp.tool(name=tool_name)(handler)
        count += 1
    return count
