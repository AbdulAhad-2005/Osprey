---
name: traffic-capture
description: >-
  Full-session passive HTTP(S) capture and repeater (mitmproxy-backed) for
  when you need everything sent across an open-ended session, not just one
  browser_flow step sequence. Use when testing IDOR/auth-bypass/param-
  pollution across many organic requests, or when you want a persistent
  history to replay from later. Do not use for a single scripted flow —
  browser_flow's own captured_requests+replay already covers that in one call.
phases: [web, exploit]
tags: [proxy, mitmproxy, capture, replay, repeater, idor]
requires_tools: [mitmdump]
---

# Full-session traffic capture

`browser_flow`'s `captured_requests`/`replay` are scoped to one declared step sequence — fine for
a single login-then-tamper flow. This is for the other case: browse around organically across
many separate tool calls (or drive raw `curl`/`sqlmap` through it), then come back later and query
or replay *anything* that happened, the way a Burp/Caido history works.

## Start it

```
proxy_start(engagement_id="<eid>")
→ {"status": "started", "port": 28001, "flow_log": "/tmp/pentest/<eid>/proxy_flows.jsonl"}
```
Idempotent — calling again mid-engagement returns the same running instance instead of starting a
duplicate. One instance per `engagement_id`; concurrent engagements on the same container get
different ports automatically.

## Route traffic through it

**Browser** (`browser_flow`/`browser_scrape`) — pass the port back as `proxy_port=`:
```
browser_flow(url="https://target/login", steps=[...], proxy_port=28001)
```
No CA install needed — both browser tools already run with `ignore_https_errors=True`, so
mitmproxy's generated cert is accepted without complaint.

**`platform_shell`/`platform_script`** (curl, sqlmap, anything) — use the proxy flag directly,
`-k`/insecure to skip cert verification instead of installing the CA:
```
curl -x http://127.0.0.1:28001 -k https://target/api/thing
sqlmap -u "https://target/page?id=1" --proxy=http://127.0.0.1:28001 --proxy-cred= --skip-urlencode
```
Everything sent this way lands in the same flow log as the browser traffic — one unified history
per engagement regardless of which tool generated the request.

## Query what was captured

```
proxy_flows(engagement_id="<eid>", host="target.com", min_status=200, limit=50)
→ {"flows": [{"flow_id": 14, "method": "POST", "url": "...", "status_code": 200, ...}, ...]}

proxy_flow_detail(engagement_id="<eid>", flow_id=14)
→ full request+response headers and bodies for that one flow
```
Filter by `host`/`method`/`contains` (URL substring)/`min_status` before pulling detail — the list
view is deliberately compact (no bodies) so scanning a large capture doesn't blow context.

## Replay and tamper

```
proxy_replay(engagement_id="<eid>", flow_id=14, headers_json='{"X-User-Id": "2"}')
→ {"status_code": 200, "response_headers": {...}, "response_body": "..."}
```
This is the actual IDOR/auth-bypass workflow: capture a request as user A, replay it with A's
session cookie but B's object id / a different header value, compare the response to what A should
and shouldn't see. Works standalone against any captured flow — the browser session that
originally made it can be long closed, unlike `browser_flow`'s own `replay` step which needs a
live Playwright context's cookies.

## Clean up

```
proxy_stop(engagement_id="<eid>")
```
Always run this at engagement end — a leaked `mitmdump` holds its port indefinitely and the next
engagement sharing the container gets a confusing "already running" status for a capture that
isn't theirs.

## Do not

- Leave capture running unattended expecting it to somehow flag interesting traffic itself — it's
  a passive log + a repeater, not a scanner. Query and reason about it the same way you would a
  Burp/Caido history: you decide what's interesting.
- Assume `proxy_replay` reuses TLS session state or browser-only context (localStorage, etc.) —
  it rebuilds the request from logged headers/body over a fresh connection. For a replay that
  needs real browser session state, use `browser_flow`'s own `replay` step instead.
- Forget `-k`/`ignore_https_errors` when routing a tool through the proxy manually — without it,
  every HTTPS request fails cert verification against mitmproxy's self-signed cert.
