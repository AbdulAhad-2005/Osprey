---
name: config-and-headers
description: "Config, headers, and CORS testing (WSTG-CONF/CLNT) via platform_script: security headers, cookie flags, and CORS — one HTTP request plus logic each."
phases: [web]
tags: [web, headers, cors]
---

# Config, headers & CORS testing (WSTG-CONF / CLNT) — via platform_script

These checks are one HTTP request + logic — **write a `platform_script` (curl/python)** rather
than reaching for a tool. Record what you find as observations with honest grades. Get the
target list from `platform_context` (live URLs / crown jewels).

## Security response headers (WSTG-CONF-06 / CLNT)

Fetch headers (`curl -sI https://host` or a Python HEAD/GET) and evaluate what's **missing or
weak** — the platform captures headers but doesn't judge them:

- **Strict-Transport-Security** — missing → downgrade/MITM exposure (LOW–MEDIUM). Check `max-age`
  ≥ 15768000 and `includeSubDomains`.
- **Content-Security-Policy** — missing or `unsafe-inline`/`unsafe-eval`/`*` → weak XSS mitigation.
- **X-Frame-Options** / CSP `frame-ancestors** — missing → **clickjacking** (test by framing).
- **X-Content-Type-Options: nosniff** — missing → MIME sniffing.
- **Referrer-Policy**, **Permissions-Policy** — missing → info leak / feature exposure (LOW).
- **Server / X-Powered-By** version leakage — INFO, feeds targeted CVE lookups.

Grade OBSERVED (you read the live response); severity is LOW–MEDIUM config hygiene, not RCE.

## Cookie attributes (WSTG-SESS-02)

From `Set-Cookie`, flag session cookies missing **Secure**, **HttpOnly**, or a proper
**SameSite** (Lax/Strict). A session/auth cookie without HttpOnly is XSS-stealable (MEDIUM);
without Secure it can leak over HTTP. Identify which cookie is the session by name/behaviour.

## CORS misconfiguration (WSTG-CLNT-07)

Replay the request with an `Origin:` header you control and inspect the response:
- `Access-Control-Allow-Origin` **reflects your arbitrary Origin** AND
  `Access-Control-Allow-Credentials: true` → **HIGH** (cross-origin credentialed reads).
- `ACAO: *` with credentials, or `null` origin accepted → misconfig (MEDIUM).
- Test a few origins: evil.com, `null`, `https://host.evil.com`, and a sibling subdomain.

## HTTP methods & verb tampering (WSTG-CONF-06)

`curl -X OPTIONS -i` to list allowed methods; then probe risky ones:
- **PUT/DELETE** enabled on app paths → possible file write/delete (HIGH if it works).
- **TRACE** → Cross-Site Tracing (LOW).
- Verb tampering: does `HEAD`/`GET` bypass an auth check that blocks `POST`?

## Admin / backup / config exposure (WSTG-CONF-04/05)

Content discovery (`feroxbuster`/`ffuf`) with extensions (`-x bak,old,zip,sql,env,git,swp`)
finds these; verify each hit returns **real content** (not a soft-404) before rating. `.git/`,
`.env`, `wp-config.php.bak`, `/actuator`, `/server-status` are high-signal.

## Do not

- Rate a missing header as HIGH — it's config hygiene (LOW–MEDIUM) unless you chain it into a
  working attack (e.g. missing XFO + a sensitive action = demonstrable clickjacking).
- Claim CORS impact without confirming credentials are actually reflected + allowed.
- Report a method as enabled without confirming it does something (405 vs actual write).
