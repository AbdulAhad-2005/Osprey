#!/usr/bin/env python3
"""Declarative browser-flow driver (Playwright) — executes a sequence of steps in
ONE real Chromium session so the LLM can drive multi-step flows: login,
authenticated navigation, and business-logic tests (add-to-cart → tamper →
checkout → assert). Fits the stateless tool model: the whole flow is one call.

Steps (JSON list via --steps), each an object with "action":
  goto        {url}
  fill        {selector, value}
  click       {selector}
  press       {selector?, key}
  wait        {ms}  or  {selector}
  select      {selector, value}
  upload      {selector, files}         -> set file(s) on an <input type=file>
  extract     {selector, name}          -> captured under result.extracted[name]
  assert_text {text}                     -> records present true/false
  screenshot  {name?}                    -> saved to --screenshot-dir
  set_header  {name, value}              -> extra HTTP header for later requests
  set_cookie  {name, value, domain?}
  snapshot    {name?, limit?}            -> compact interactive-element map of the
                                            current DOM (links/forms/inputs/buttons
                                            with CSS selectors) so the agent can SEE
                                            the page mid-flow and decide the next
                                            step (Strix-style snapshot-and-act loop)
  replay      {url, method?, headers?, body?, json?, name?}
                                          -> re-send an HTTP request THROUGH the live
                                            authenticated browser session (cookies
                                            intact). Tamper any field to test IDOR /
                                            auth-bypass / param pollution, then read
                                            the full status+headers+body back. This is
                                            a session-aware HTTP repeater.

Emits JSON: steps[] (per-step ok/error/detail), final_url, title, cookies,
captured_requests (xhr/fetch with headers+post_data — replayable), snapshots{},
replays[], extracted{}, asserts[]. Never raises to the shell.
"""

from __future__ import annotations

import argparse
import json
import os
import sys


_SNAPSHOT_JS = """
() => {
  const pick = (el) => {
    let sel = el.tagName.toLowerCase();
    if (el.id) sel += '#' + CSS.escape(el.id);
    else if (el.name) sel += `[name="${el.name}"]`;
    const t = (el.innerText || el.value || el.getAttribute('placeholder') || el.getAttribute('aria-label') || '').trim().slice(0, 80);
    const rec = { tag: el.tagName.toLowerCase(), selector: sel, text: t };
    if (el.tagName === 'A' && el.href) rec.href = el.href;
    if (el.tagName === 'INPUT') { rec.type = el.type; rec.name = el.name || ''; }
    if (el.tagName === 'FORM') { rec.action = el.action || ''; rec.method = (el.method || 'get'); }
    return rec;
  };
  const els = Array.from(document.querySelectorAll('a[href],button,input,select,textarea,form,[role=button],[onclick]'));
  return els.map(pick);
}
"""


def _snapshot_interactive(page, limit: int) -> list:
    try:
        items = page.evaluate(_SNAPSHOT_JS) or []
    except Exception as exc:  # noqa: BLE001
        return [{"error": str(exc)[:160]}]
    # Drop empty/duplicate rows, cap for context size.
    seen = set()
    out = []
    for it in items:
        key = (it.get("tag"), it.get("selector"), it.get("text"))
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
        if len(out) >= max(1, limit):
            break
    return out


def _replay_request(context, step: dict, timeout_ms: int) -> dict:
    """Re-send an HTTP request via the browser context's APIRequestContext so the
    live session (cookies) is reused. Returns full status/headers/body."""
    url = str(step.get("url") or "").strip()
    if not url:
        return {"error": "replay requires url="}
    method = str(step.get("method") or "GET").upper()
    headers = step.get("headers") or {}
    kwargs = {"method": method, "headers": headers, "timeout": timeout_ms}
    if step.get("json") is not None:
        kwargs["data"] = json.dumps(step["json"])
        headers.setdefault("content-type", "application/json")
    elif step.get("body") is not None:
        kwargs["data"] = step["body"]
    try:
        resp = context.request.fetch(url, **kwargs)
        body = resp.text()
        return {
            "url": url,
            "method": method,
            "status": resp.status,
            "ok": resp.ok,
            "headers": dict(resp.headers),
            "body_len": len(body or ""),
            "body": (body or "")[:6000],
            "name": step.get("name", ""),
        }
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "method": method, "error": str(exc)[:240]}


def _run(start_url: str, steps: list, *, timeout_ms: int, screenshot_dir: str) -> dict:
    from playwright.sync_api import sync_playwright

    out: dict = {
        "start_url": start_url, "final_url": "", "title": "",
        "steps": [], "cookies": [], "captured_requests": [],
        "snapshots": {}, "replays": [],
        "extracted": {}, "asserts": [], "errors": [],
    }
    captured: list[dict] = []
    extra_headers: dict[str, str] = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        )
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.set_default_timeout(timeout_ms)

        def _on_request(req):
            # Capture the FULL request (headers + body), not just url+method, so a
            # captured API call is actually replayable/tamperable downstream.
            if req.resource_type in ("xhr", "fetch"):
                try:
                    post = req.post_data
                except Exception:
                    post = None
                try:
                    hdrs = dict(req.headers)
                except Exception:
                    hdrs = {}
                captured.append({
                    "url": req.url,
                    "method": req.method,
                    "resource_type": req.resource_type,
                    "headers": hdrs,
                    "post_data": (post or "")[:4000] if post else "",
                })
        page.on("request", _on_request)

        if start_url:
            try:
                page.goto(start_url, timeout=timeout_ms, wait_until="domcontentloaded")
            except Exception as exc:  # noqa: BLE001
                out["errors"].append(f"initial goto: {exc}"[:300])

        for idx, step in enumerate(steps):
            action = str(step.get("action", "")).lower()
            rec = {"i": idx, "action": action, "ok": False, "detail": ""}
            try:
                if action == "goto":
                    page.goto(step["url"], timeout=timeout_ms, wait_until="domcontentloaded")
                elif action == "fill":
                    page.fill(step["selector"], str(step.get("value", "")))
                elif action == "click":
                    page.click(step["selector"])
                elif action == "press":
                    if step.get("selector"):
                        page.press(step["selector"], step["key"])
                    else:
                        page.keyboard.press(step["key"])
                elif action == "select":
                    page.select_option(step["selector"], str(step.get("value", "")))
                elif action == "upload":
                    # File upload testing (WSTG): set a file on an <input type=file>.
                    # path(s) created beforehand via platform_script.
                    files = step.get("files") or step.get("path") or step.get("value")
                    page.set_input_files(step["selector"], files)
                    rec["detail"] = str(files)[:120]
                elif action == "wait":
                    if step.get("selector"):
                        page.wait_for_selector(step["selector"], timeout=timeout_ms)
                    else:
                        page.wait_for_timeout(int(step.get("ms", 1000)))
                elif action == "extract":
                    val = page.inner_text(step["selector"])
                    out["extracted"][step.get("name", f"extract_{idx}")] = (val or "")[:1000]
                    rec["detail"] = (val or "")[:120]
                elif action == "assert_text":
                    text = str(step.get("text", ""))
                    present = False
                    try:
                        present = text in (page.content() or "")
                    except Exception:
                        present = False
                    out["asserts"].append({"text": text[:120], "present": present})
                    rec["detail"] = f"present={present}"
                elif action == "screenshot":
                    if screenshot_dir:
                        os.makedirs(screenshot_dir, exist_ok=True)
                        name = step.get("name") or f"step_{idx}"
                        path = os.path.join(screenshot_dir, f"{name}.png")
                        page.screenshot(path=path, full_page=True)
                        rec["detail"] = path
                elif action == "set_header":
                    extra_headers[str(step["name"])] = str(step.get("value", ""))
                    page.set_extra_http_headers(extra_headers)
                elif action == "set_cookie":
                    context.add_cookies([{
                        "name": step["name"], "value": str(step.get("value", "")),
                        "url": step.get("url") or page.url,
                    }])
                elif action == "snapshot":
                    # Compact, see-then-act view of the live DOM (Strix-style): the
                    # interactive elements with stable CSS selectors, so the agent can
                    # decide its next step without parsing raw HTML.
                    limit = int(step.get("limit", 60))
                    snap = _snapshot_interactive(page, limit)
                    name = step.get("name") or f"snapshot_{idx}"
                    out["snapshots"][name] = snap
                    rec["detail"] = f"{len(snap)} elements"
                elif action == "replay":
                    # Session-aware HTTP repeater: re-send through the authenticated
                    # browser context so cookies/session are preserved. Tamper any
                    # field to test IDOR / auth-bypass / parameter pollution.
                    rep = _replay_request(context, step, timeout_ms)
                    out["replays"].append(rep)
                    rec["detail"] = f"status={rep.get('status')} bytes={rep.get('body_len')}"
                else:
                    rec["detail"] = f"unknown action '{action}'"
                    out["steps"].append(rec)
                    continue
                rec["ok"] = True
            except Exception as exc:  # noqa: BLE001
                rec["detail"] = str(exc)[:200]
            out["steps"].append(rec)

        out["final_url"] = page.url
        try:
            out["title"] = page.title()
        except Exception:
            pass
        try:
            for c in context.cookies():
                out["cookies"].append({
                    "name": c.get("name"), "httpOnly": c.get("httpOnly"),
                    "secure": c.get("secure"), "sameSite": c.get("sameSite"),
                })
        except Exception:
            pass
        context.close()
        browser.close()

    seen = set()
    uniq = []
    for r in captured:
        k = (r["method"], r["url"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    out["captured_requests"] = uniq[:300]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="")
    ap.add_argument("--steps", required=True, help="JSON list of step objects")
    ap.add_argument("--timeout-ms", type=int, default=30000)
    ap.add_argument("--screenshot-dir", default="")
    args = ap.parse_args()
    try:
        steps = json.loads(args.steps)
        if not isinstance(steps, list):
            raise ValueError("--steps must be a JSON list")
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"errors": [f"bad --steps: {exc}"], "steps": []}))
        return 0
    try:
        out = _run(args.url, steps, timeout_ms=args.timeout_ms, screenshot_dir=args.screenshot_dir)
    except Exception as exc:  # noqa: BLE001
        out = {"errors": [f"fatal: {exc}"], "steps": []}
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
