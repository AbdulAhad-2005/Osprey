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

Emits JSON: steps[] (per-step ok/error/detail), final_url, title, cookies,
captured_requests (xhr/fetch), extracted{}, asserts[]. Never raises to the shell.
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def _run(start_url: str, steps: list, *, timeout_ms: int, screenshot_dir: str) -> dict:
    from playwright.sync_api import sync_playwright

    out: dict = {
        "start_url": start_url, "final_url": "", "title": "",
        "steps": [], "cookies": [], "captured_requests": [],
        "extracted": {}, "asserts": [], "errors": [],
    }
    captured: list[dict] = []
    extra_headers: dict[str, str] = {}
    shot_i = 0

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        )
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.set_default_timeout(timeout_ms)

        def _on_request(req):
            if req.resource_type in ("xhr", "fetch"):
                captured.append({"url": req.url, "method": req.method})
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
