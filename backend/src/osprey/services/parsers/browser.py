"""Parsers for the Playwright browser tools (browser_scrape / browser_flow).

Turn rendered-DOM output into attack-surface Observations: client-side routes,
XHR/fetch API endpoints, form inputs (injection-point candidates), cookie-flag
facts, mixed content, and a structured trace of driven flows for the earned-
finding pipeline (Plan 03) to reason about. A parser extracts structure only —
"cookie X lacks HttpOnly" is a fact; whether that earns a VULNERABILITY
finding is `confidence_for`'s job, never this module's.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from osprey.schemas.observation import Observation, ObservationType

_INTERESTING = ("/api", "/admin", "/graphql", "/internal", "/upload", "/token",
                "/oauth", "/sso", "/debug", "/actuator", "/.git", "/config")


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except ValueError:
        return ""


def _load(stdout: str) -> dict | None:
    text = (stdout or "").strip()
    start = text.find("{")
    if start == -1:
        return None
    try:
        data = json.loads(text[start:])
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def _cookie_observations(cookies, *, tool, engagement_id, run_id, target, url):
    out = []
    for c in cookies or []:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or "")
        looks_session = any(k in name.lower() for k in ("sess", "sid", "auth", "token", "jwt", "login"))
        missing = []
        if c.get("httpOnly") is False:
            missing.append("HttpOnly")
        if c.get("secure") is False:
            missing.append("Secure")
        same = str(c.get("sameSite") or "").lower()
        if same in ("", "none"):
            missing.append("SameSite")
        if missing and looks_session:
            out.append(Observation(
                engagement_id=engagement_id, run_id=run_id,
                type=ObservationType.COOKIE,
                target=url or target, source_tool=tool,
                details={
                    "cookie": name,
                    "missing_flags": missing,
                    "looks_session": True,
                    "url": url or target,
                    "raw": json.dumps(c, sort_keys=True)[:300],
                },
            ))
    return out


def parse_browser_scrape(stdout, *, engagement_id="", run_id="", target=""):
    data = _load(stdout)
    if data is None:
        return _unparsed(stdout, "browser_scrape", engagement_id, run_id, target)
    url = str(data.get("final_url") or data.get("url") or target)
    out: list[Observation] = []

    # Discovered client-side links → URL attack surface.
    for link in (data.get("links") or [])[:200]:
        low = str(link).lower()
        interesting = any(m in low for m in _INTERESTING)
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.URL,
            target=str(link), source_tool="browser_scrape",
            details={
                "url": str(link)[:200],
                "hostname": _host(link),
                "kind": "rendered_link",
                "interesting": interesting,
                "injection_point_candidate": interesting,
            },
        ))

    # XHR/fetch → live API endpoints (high-value surface).
    for x in (data.get("xhr") or [])[:200]:
        xurl = str(x.get("url") or "")
        if not xurl:
            continue
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.URL,
            target=xurl, source_tool="browser_scrape",
            details={
                "url": xurl,
                "hostname": _host(xurl),
                "method": str(x.get("method") or "GET"),
                "kind": "xhr",
                "injection_point_candidate": True,
            },
        ))

    # Forms → each named input is an injection-point candidate.
    for form in (data.get("forms") or [])[:60]:
        action = str(form.get("action") or url)
        for inp in (form.get("inputs") or []):
            name = str(inp.get("name") or "")
            if not name:
                continue
            out.append(Observation(
                engagement_id=engagement_id, run_id=run_id,
                type=ObservationType.INJECTION_POINT,
                target=action, source_tool="browser_scrape",
                details={
                    "parameter": name,
                    "url": action,
                    "method": str(form.get("method") or "GET"),
                    "input_type": str(inp.get("type") or ""),
                    "kind": "form_field",
                },
            ))

    out.extend(_cookie_observations(data.get("cookies"), tool="browser_scrape",
               engagement_id=engagement_id, run_id=run_id, target=target, url=url))

    # Mixed content on an HTTPS page.
    if data.get("mixed_content"):
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.HTTP_RESPONSE,
            target=url, source_tool="browser_scrape",
            details={
                "kind": "mixed_content",
                "hostname": _host(url),
                "resource_count": len(data["mixed_content"]),
                "resources": [str(m) for m in data["mixed_content"][:8]],
            },
        ))
    return out or _unparsed(stdout, "browser_scrape", engagement_id, run_id, target)


def parse_browser_flow(stdout, *, engagement_id="", run_id="", target=""):
    data = _load(stdout)
    if data is None:
        return _unparsed(stdout, "browser_flow", engagement_id, run_id, target)
    out: list[Observation] = []
    final_url = str(data.get("final_url") or target)
    steps = data.get("steps") or []
    ok = sum(1 for s in steps if s.get("ok"))
    failed = [s for s in steps if not s.get("ok")]

    # Flow trace — the earned-finding pipeline (LLM/human via file_finding, or
    # promote_observations) interprets this against intended business logic.
    out.append(Observation(
        engagement_id=engagement_id, run_id=run_id,
        type=ObservationType.SCANNER_SIGNAL,
        target=final_url, source_tool="browser_flow",
        details={
            "kind": "browser_flow_trace",
            "steps_ok": ok,
            "steps_total": len(steps),
            "had_step_errors": bool(failed),
            "final_url": final_url,
            "steps": steps[:20],
            "asserts": data.get("asserts"),
            "extracted": data.get("extracted"),
        },
    ))

    # Assertions are business-logic evidence.
    for a in data.get("asserts") or []:
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.SCANNER_SIGNAL,
            target=final_url, source_tool="browser_flow",
            details={"kind": "flow_assertion", "assertion": a},
        ))

    # Captured API calls during the (possibly authenticated) flow.
    for r in (data.get("captured_requests") or [])[:120]:
        rurl = str(r.get("url") or "")
        if not rurl:
            continue
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.URL,
            target=rurl, source_tool="browser_flow",
            details={
                "url": rurl,
                "hostname": _host(rurl),
                "method": str(r.get("method") or "GET"),
                "kind": "captured_request",
                "authenticated": True,
                "injection_point_candidate": True,
            },
        ))

    # Replayed (tampered) requests — the session-aware repeater. The status
    # code is the fact; whether a 2xx on a tampered cross-user request is an
    # IDOR is a judgment the earned-finding pipeline makes from this evidence.
    for r in (data.get("replays") or [])[:60]:
        rurl = str(r.get("url") or "")
        if not rurl or r.get("error"):
            continue
        status = r.get("status")
        authorized = isinstance(status, int) and 200 <= status < 300
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.SCANNER_SIGNAL,
            target=rurl, source_tool="browser_flow",
            details={
                "kind": "authenticated_replay",
                "method": str(r.get("method") or "GET"),
                "url": rurl,
                "status": status,
                "body_len": r.get("body_len"),
                "returned_2xx": authorized,
            },
        ))

    out.extend(_cookie_observations(data.get("cookies"), tool="browser_flow",
               engagement_id=engagement_id, run_id=run_id, target=target, url=final_url))
    return out


def _unparsed(stdout, tool, engagement_id, run_id, target):
    stripped = (stdout or "").strip()
    if not stripped:
        return []
    return [Observation(
        engagement_id=engagement_id, run_id=run_id,
        type=ObservationType.RAW,
        target=target, source_tool=tool,
        details={"snippet": stripped[:2000]},
    )]


def _register_browser_parsers() -> None:
    from osprey.services.parsers.registry import register_output_parser
    register_output_parser("browser_scrape", parse_browser_scrape)
    register_output_parser("browser_flow", parse_browser_flow)


_register_browser_parsers()
