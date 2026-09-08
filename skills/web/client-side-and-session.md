---
name: client-side-and-session
description: "Client-side and session testing (WSTG-CLNT/SESS/ATHZ): DOM XSS, session, and authorization issues that need the real DOM or a real session via browser tools."
phases: [web]
tags: [web, dom-xss, session]
---

# Client-side & session testing (WSTG-CLNT / SESS / ATHZ)

These need the real DOM or a real session — `browser_flow` / `browser_scrape`, sometimes with a
`platform_script` to replay a captured request. Static tools can't reach them.

## DOM-based XSS (WSTG-CLNT-01)

Reflected/stored XSS is `dalfox`'s job; **DOM XSS** fires entirely client-side (a sink like
`innerHTML`/`document.write`/`eval` reads a source like `location.hash`/`postMessage`). Test with
`browser_flow`: `goto` the page with a payload in the source (e.g. `#<img src=x onerror=...>`),
then `assert_text`/screenshot or check console for execution. `js_recon` helps locate the sink
in the bundle first.

## Session management (WSTG-SESS)

- **Cookie flags** — `browser_scrape` reports Secure/HttpOnly/SameSite; a session cookie missing
  HttpOnly is XSS-stealable (MEDIUM), missing Secure leaks over HTTP.
- **Session fixation** — capture the pre-login session id, log in via `browser_flow`, check
  whether the id **rotates** after auth. No rotation = fixation (MEDIUM).
- **Logout / timeout** — after logout, replay a captured authenticated request (`platform_script`
  with the old cookie) — if it still works, logout doesn't invalidate server-side (MEDIUM).
- **Token entropy** — analyse session-token structure (length, predictability) from the cookies.

## CSRF (WSTG-SESS-05)

For a state-changing request captured during a `browser_flow` session, check whether it carries
an **anti-CSRF token** tied to the session and validated server-side. Replay it via
`platform_script` **without** the token (but with the session cookie) — if it succeeds, CSRF is
viable (severity by the action's impact). SameSite=Strict/Lax mitigates; note it.

## Authorization — IDOR & privilege escalation (WSTG-ATHZ)

The high-value auth tests, and they need **two authenticated contexts**:
- **IDOR** — log in as user A (`browser_flow`), capture a request with an object id
  (`/api/order/1001`). Then, as user B (a second `browser_flow` session, or replay with B's
  cookie), request A's id — if you get A's data, that's IDOR (severity by data sensitivity).
- **Vertical priv-esc** — as a low-priv user, request an admin endpoint/function you enumerated;
  if it works, that's broken access control.
- **Parameter role flags** — flip `role`/`isAdmin`/`account_type` in a captured request and replay.

## CORS (WSTG-CLNT-07)

Covered by script in `config-and-headers` — replay with a controlled `Origin`. Use the browser
only to confirm a real cross-origin credentialed read is possible when the headers look exploitable.

## Do not

- Access another real user's data beyond authorised test accounts — use two *test* users for IDOR.
- Claim CSRF/IDOR without a working replay proving the action succeeded cross-context.
- Rate a missing cookie flag as HIGH on its own — it's MEDIUM unless chained into a working theft.
