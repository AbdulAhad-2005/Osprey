#!/usr/bin/env python3
"""Headless-browser scraper (Playwright) — renders a page in real Chromium and
extracts the attack surface a static crawler misses on JS/SPA apps.

Emits a single JSON object on stdout:
  final_url, status, title, response_headers, cookies (with flags),
  links, forms (action/method/inputs), xhr (captured fetch/XHR endpoints),
  console_errors, mixed_content, screenshot path, dom_text_excerpt.

Runs inside the Kali container where Playwright + Chromium are installed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from urllib.parse import urljoin, urlparse


def _run(url: str, *, timeout_ms: int, wait_until: str, screenshot_path: str, max_items: int) -> dict:
    from playwright.sync_api import sync_playwright  # provisioned in the image

    result: dict = {
        "url": url, "final_url": "", "status": None, "title": "",
        "response_headers": {}, "cookies": [], "links": [], "forms": [],
        "xhr": [], "console_errors": [], "mixed_content": [],
        "screenshot": "", "dom_text_excerpt": "", "errors": [],
    }
    xhr: list[dict] = []
    console_errors: list[str] = []
    base_is_https = urlparse(url).scheme == "https"
    mixed: set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        def _on_request(req):
            rt = req.resource_type
            if rt in ("xhr", "fetch"):
                xhr.append({"url": req.url, "method": req.method, "resource_type": rt})
            if base_is_https and req.url.startswith("http://"):
                mixed.add(req.url)

        def _on_console(msg):
            if msg.type in ("error", "warning"):
                console_errors.append(f"[{msg.type}] {msg.text}"[:300])

        page.on("request", _on_request)
        page.on("console", _on_console)

        try:
            resp = page.goto(url, timeout=timeout_ms, wait_until=wait_until)
            if resp is not None:
                result["status"] = resp.status
                try:
                    result["response_headers"] = dict(resp.headers)
                except Exception:
                    pass
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"navigation: {exc}"[:300])

        # Let late XHR/render settle.
        try:
            page.wait_for_timeout(1500)
        except Exception:
            pass

        result["final_url"] = page.url
        try:
            result["title"] = page.title()
        except Exception:
            pass

        # Links (resolved absolute).
        try:
            hrefs = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.getAttribute('href'))"
            )
            links: list[str] = []
            seen = set()
            for h in hrefs or []:
                if not h:
                    continue
                absu = urljoin(page.url, h)
                if absu.startswith(("http://", "https://")) and absu not in seen:
                    seen.add(absu)
                    links.append(absu)
            result["links"] = links[:max_items]
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"links: {exc}"[:200])

        # Forms + inputs (each input is an injection-point candidate).
        try:
            forms = page.eval_on_selector_all(
                "form",
                """els => els.map(f => ({
                    action: f.getAttribute('action') || '',
                    method: (f.getAttribute('method') || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(i => ({
                        name: i.getAttribute('name') || '',
                        type: i.getAttribute('type') || i.tagName.toLowerCase()
                    })).filter(i => i.name)
                }))""",
            )
            for f in forms or []:
                f["action"] = urljoin(page.url, f.get("action") or "") or page.url
            result["forms"] = (forms or [])[:max_items]
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"forms: {exc}"[:200])

        # Cookies with security flags.
        try:
            for c in context.cookies():
                result["cookies"].append({
                    "name": c.get("name"), "httpOnly": c.get("httpOnly"),
                    "secure": c.get("secure"), "sameSite": c.get("sameSite"),
                })
        except Exception:
            pass

        # DOM text excerpt.
        try:
            result["dom_text_excerpt"] = (page.inner_text("body") or "")[:4000]
        except Exception:
            pass

        if screenshot_path:
            try:
                page.screenshot(path=screenshot_path, full_page=True)
                result["screenshot"] = screenshot_path
            except Exception as exc:  # noqa: BLE001
                result["errors"].append(f"screenshot: {exc}"[:200])

        context.close()
        browser.close()

    # De-dupe xhr by (method,url).
    seen_x = set()
    uniq_xhr = []
    for x in xhr:
        key = (x["method"], x["url"])
        if key not in seen_x:
            seen_x.add(key)
            uniq_xhr.append(x)
    result["xhr"] = uniq_xhr[:max_items]
    result["mixed_content"] = sorted(mixed)[:max_items]
    result["console_errors"] = console_errors[:30]
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--timeout-ms", type=int, default=30000)
    ap.add_argument("--wait-until", default="networkidle",
                    choices=["load", "domcontentloaded", "networkidle", "commit"])
    ap.add_argument("--screenshot", default="")
    ap.add_argument("--max-items", type=int, default=300)
    args = ap.parse_args()
    try:
        out = _run(args.url, timeout_ms=args.timeout_ms, wait_until=args.wait_until,
                   screenshot_path=args.screenshot, max_items=args.max_items)
    except Exception as exc:  # noqa: BLE001
        out = {"url": args.url, "errors": [f"fatal: {exc}"], "links": [], "forms": [], "xhr": []}
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
