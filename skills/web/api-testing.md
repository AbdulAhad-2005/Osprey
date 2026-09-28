---
name: api-testing
description: "API testing (WSTG-APIT / OWASP API Security Top 10 2023): REST/GraphQL-specific classes scanners miss — BOLA, mass assignment, function-level authz, resource exhaustion. Use response_diff_confirm/canary_confirm for deterministic proof."
phases: [web]
tags: [web, api, bola, idor, rest, graphql]
---

# API testing (WSTG-APIT / OWASP API Security Top 10)

APIs are a *different* attack surface from the pages that call them — the same
authorization/business-logic bugs as regular web testing, but concentrated, because every
endpoint is an explicit, parameterized operation with no UI in the way to accidentally hide a
bad idea. Treat any `/api`, `/v1`, `/v2`, `/rest`, `/graphql` path (already flagged
"interesting" by content-discovery/js_recon) as its own testing target, not an afterthought of
page-level testing.

## API1:2023 — Broken Object Level Authorization (BOLA) — the #1 API bug, by far

Every endpoint that takes an object id (`/api/orders/123`, `?user_id=45`,
`{"invoiceId": "..."}`) needs this check: **can user A read/modify user B's object by changing
the id alone?**

Method (deterministic, not a guess):
1. Get two authenticated sessions/tokens for the same app, different accounts — a low-priv
   test account is normally in scope; ask the operator if only one account is available.
2. Capture a legitimate request for account A's own object (`proxy_start` + `proxy_flows`, or
   `browser_flow` network capture).
3. Replay the *identical* request with account B's token/cookie via `proxy_replay`, or fetch
   both directly and use **`response_diff_confirm`** — url_a = A's object under A's session,
   url_b = the SAME object id under B's session (headers_json carries each session's auth). A
   `200` with the real data on url_b, or `identical: true` between "my own object" and
   "someone else's object", is the deterministic proof — not your own read of two JSON blobs.
4. Sequential/guessable ids (auto-increment, non-UUID) make this worse — enumerate a small
   range rather than testing one id in isolation.

## API3:2023 — Broken Object Property Level Authorization (excessive data exposure / mass assignment)

- **Excessive data exposure**: does the response include fields the UI never renders
  (`is_admin`, `password_hash`, `internal_notes`, another user's PII nested in a list)? Fetch
  the raw response (not what the rendered page shows) and read every key.
  `advanced-injection-classes.md` covers the request-side twin of this (mass assignment: does
  the API accept and apply a field it shouldn't, like `{"role": "admin"}` on a profile-update
  call) — same family, opposite direction (response leaks vs. request over-binds).

## API5:2023 — Broken Function Level Authorization

The authz equivalent of BOLA but for *actions*, not objects: can a low-priv account call an
admin-only endpoint directly (`POST /api/admin/users/delete`) even though the UI never shows it
that role? Diff the API surface between roles (`js_recon`/`browser_scrape` on each role's
session) — an endpoint only the admin UI references, called directly with a low-priv token, is
the check. `response_diff_confirm` between "admin session" and "low-priv session" hitting the
identical endpoint is the deterministic proof, same shape as BOLA above.

## API4:2023 — Unrestricted Resource Consumption

No rate limit / pagination cap / max-page-size on an expensive endpoint (search, export,
bulk-fetch). Cheap check: request a large `limit`/`page_size`/date-range and see if the API
honors it uncapped, and whether repeated calls in a short window ever get throttled — a few
requests is enough to observe the absence of a limit; don't turn this into a DoS attempt.

## API7:2023 — Server-Side Request Forgery

Any API param that takes a URL/webhook/callback (`imageUrl`, `webhookUrl`, `callback`) —
see `advanced-injection-classes.md`'s SSRF section; `canary_confirm` against your own
listener/interactsh URL is the deterministic proof a fetch actually happened server-side.

## API9:2023 — Improper Inventory Management

Old API versions (`/v1/` still live next to `/v3/`) often skip the newer version's auth/authz
fixes — `waybackurls_discovery`/`gau_discovery` surface deprecated paths; test the SAME BOLA/
authz checks above against the old version specifically, it's frequently the softer target.

## GraphQL specifics

`graphql_cop_scan` covers introspection exposure and batching/aliasing abuse mechanically —
still do the BOLA/function-authz checks above per-query/mutation, since GraphQL's single
endpoint hides many "different endpoints" behind one URL; `graphql-testing.md` (browser skills)
covers the introspection-driven schema-walk this depends on.

## Turning it into a finding

Same evidence law as everything else — `platform_file_finding(evidence_kind='reproduction')`
needs a real excerpt from a `response_diff_confirm`/`canary_confirm`/`proxy_replay` observation,
not a description of what you think happened. A BOLA finding's evidence is the diff itself
(status/body showing account B's data returned to account A's session), not "I tested this and
it's vulnerable."
