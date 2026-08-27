---
name: browser-automation
description: "Browser automation with browser_scrape (one-shot SPA render plus attack-surface extract) and browser_flow (authenticated multi-step session with a live-DOM snapshot loop and a session-aware HTTP repeater) for authenticated, client-side, and access-control testing."
phase: web
tags: [web, browser, spa]
---

# Browser automation (browser_scrape & browser_flow)

Two Playwright-backed tools give you a **real rendered browser** — the capability that unlocks
SPA scraping, authenticated testing, client-side bugs, and business logic. Static tools
(`httpx`, `katana -jc`, `js_recon`) see the served HTML; these see the DOM the app actually
builds and the requests it actually makes.

## browser_scrape (url=) — one-shot render + extract

Renders the page in headless Chromium (waits for network idle) and returns:
- **links** — client-side/SPA routes (`<a href>` after render).
- **xhr** — the real XHR/fetch **API endpoints** the app calls at runtime (highest-value surface).
- **forms** — action/method + every named input (each is an injection-point candidate).
- **cookies** — with Secure/HttpOnly/SameSite flags (session-cookie issues become findings).
- **mixed_content**, console errors, and a full-page **screenshot** (saved as an artifact).

Use it on every JS/SPA app host (React/Vue/Angular/Next/Svelte) before deeper testing — it
recovers routes and APIs that `feroxbuster`/`katana` alone miss. The captured XHR endpoints feed
content discovery, parameter testing, and the vuln phase.

## browser_flow (steps=, url=) — drive a multi-step session

Executes a **declarative step list** (JSON) in ONE browser session, so you can log in and act as
a user. You author the steps; the tool runs them and returns a per-step trace, captured API
calls, extracted values, assertion results, and final cookies.

**Step actions:** `goto{url}`, `fill{selector,value}`, `click{selector}`, `press{selector?,key}`,
`wait{ms|selector}`, `select{selector,value}`, `upload{selector,files}` (file-upload testing —
create the test file first with `platform_script`), `extract{selector,name}`, `assert_text{text}`,
`screenshot{name?}`, `set_header{name,value}`, `set_cookie{name,value}`,
`snapshot{name?,limit?}`, `replay{url,method?,headers?,body?,json?,name?}`.

## snapshot — see the page, then act (don't pre-guess selectors)

You don't always know a page's structure up front. `snapshot` returns a **compact map of the live
DOM's interactive elements** (links, buttons, inputs, forms) each with a **CSS selector** and its
text/label — ~1 line per element, not raw HTML. Drive the human loop: `goto` → `snapshot` → read
the returned selectors → `fill`/`click` the right ones → `snapshot` again after the page changes.
This is far more robust on unfamiliar apps than guessing `#username` blind. Put a `snapshot` step
right after any `goto`/`click` that changes the page, then use the returned selectors in later
steps (or in a follow-up `browser_flow` call).

## replay — the session-aware HTTP repeater (IDOR / broken access control)

`replay` re-sends an HTTP request **through the live logged-in browser session** (cookies intact),
so it's a Buron/Caido-style **repeater that reuses your real auth** — no proxy to configure. Every
XHR the app makes is captured with its **headers and body** (`captured_requests`), so the loop is:
1. Log in and exercise the feature so the real API call is captured.
2. `replay` that request with **one field tampered** — a different object id, a stripped auth
   header, a role/price/quantity changed, an added `?admin=true`.
3. Read the returned **status + body**. A 2xx (or the victim's data) on a request you tampered to
   act cross-user is **IDOR / broken object-level authorization** — confirm impact, then record it.

**IDOR example** (capture your own order, replay someone else's):
```json
[{"action":"goto","url":"https://app/orders/123"},
 {"action":"wait","ms":1500},
 {"action":"replay","url":"https://app/api/orders/124","method":"GET","name":"idor-124"},
 {"action":"replay","url":"https://app/api/orders/125","method":"GET","name":"idor-125"}]
```
Tamper method/headers/body too — e.g. replay a `POST` with `{"role":"admin"}` (mass assignment),
or replay with `set_header` having removed the CSRF/authorization header (auth-bypass). Replays that
return 2xx are surfaced tagged `access-control-candidate` for you to confirm.

**Login example** (then confirm you're in):
```json
[{"action":"goto","url":"https://app/login"},
 {"action":"fill","selector":"#username","value":"user@test"},
 {"action":"fill","selector":"#password","value":"Passw0rd!"},
 {"action":"click","selector":"button[type=submit]"},
 {"action":"wait","selector":"nav.user-menu"},
 {"action":"assert_text","text":"Dashboard"}]
```

Because the whole flow is one call, the session (cookies/localStorage) persists across the steps.
Chain flows: scrape → identify the login form's selectors → drive `browser_flow` to authenticate →
then scrape/act as the authenticated user. Use `set_cookie`/`set_header` to reuse a session token
you already obtained (e.g. from a prior login or from js_recon).

## When to use which

- **Discovery / SPA surface** → `browser_scrape`.
- **Anything needing a session or multiple steps** (auth, CSRF, IDOR, workflow) → `browser_flow`.
   See `business-logic` and `client-side-and-session`.
- **Static/fast is enough** (server-rendered, you just want links) → stick with `katana_crawl`
   (add `-headless` for a light render) — don't spin up a full browser for a simple page.

## Do not

- Submit destructive actions (delete/purchase/transfer) during a flow without authorisation —
  driving the browser makes real requests as the user.
- Enter real user credentials you weren't given; use provided test accounts.
- Treat a screenshot as proof of a vuln — it's evidence to support a finding, not the finding.
