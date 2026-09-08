---
name: web-overview
description: "Web-application testing phase overview mapped to OWASP WSTG: when to reach for a tool, a browser, or a platform_script; follow evidence rather than a fixed stage."
phases: [web]
tags: [web, overview, wstg]
---

# Web Application Testing (OWASP WSTG map)

Focus on HTTP(S) apps once live hosts/URLs exist in memory. This overlay maps the WSTG
categories to how you test each on this platform — and, crucially, **whether to reach for a
tool, a browser, or just write a `platform_script`**. Not a mandatory stage; follow evidence.

## The three ways you test here

1. **Dedicated tool** — when the check needs a specialized engine you can't reproduce in a
   script: SQLi (`sqlmap_scan`), XSS verify (`dalfox_xss_scan`), templates/CVEs (`nuclei_scan`),
   TLS handshake (`sslyze_scan`), CMS (`wpscan_analyze`), GraphQL (`graphql_cop_scan`).
2. **`platform_script` you write** — for checks that are just an HTTP request + logic: security
   headers, cookie flags, CORS, HTTP methods, host-header injection, account-enumeration
   differentials, HTML-comment leakage. A dedicated tool would be thin and redundant — write
   the curl/python yourself. See `config-and-headers` and `identity-and-auth`.
3. **Rendered browser** — for anything that needs the real DOM or a session: SPA scraping
   (`browser_scrape`), authenticated flows / business logic / client-side (`browser_flow`).
   See the browser skills.

## WSTG coverage on this platform

- **INFO** (Information Gathering) — recon phase: subdomain/CT/DNS, httpx, tech fingerprint,
   `js_recon` (endpoints/secrets), `katana_crawl` (add `-headless` for SPAs), `well_known_probe`.
- **CONF** (Configuration/Deployment) — `nikto_scan`, `sslyze_scan` (TLS), + **script**: security
   headers, HTTP methods, admin/backup files (content discovery), CORS. → `config-and-headers`.
- **CRYP** (Cryptography) — `sslyze_scan`. → `tls-configuration` (vuln skills).
- **IDENT** (Identity) — **script**: account/username enumeration via response differentials.
   → `identity-and-auth`.
- **ATHN** (Authentication) — default creds (`nuclei` default-login, `hydra`), password policy,
   lockout; login flows need a **browser** (`browser_flow`). → `identity-and-auth`. OAuth/OIDC/SSO
   + JWT (account takeover) → `oauth-and-jwt`.
- **ATHZ** (Authorization) — traversal (`nuclei`/dotdotpwn); IDOR / priv-esc need **authenticated
   browser sessions** (`browser_flow`, two users). → browser skills.
- **SESS** (Session) — cookie flags via **script**; CSRF / fixation / logout need a **browser**.
- **INPV** (Input Validation) — `sqlmap_scan`, `dalfox_xss_scan`, `nuclei_scan` (LFI/SSTI/SSRF/cmdi
   via tags). → vuln skills (`injection-testing`, and `advanced-injection-classes` for
   SSRF/SSTI/XXE/deserialization/NoSQL/mass-assignment).
- **CLNT** (Client-Side) — DOM XSS / postMessage / storage need a **browser** (`browser_flow`).
- **BUSLOGIC** (Business Logic) — **browser + your reasoning**. → `business-logic` (browser skills).

## Operate

1. `platform_context()` — read inferred focus + gaps + crown jewels.
2. Prioritise high-value apps (login, admin, API, upload, SSO, payment) from the attack-surface
   tree — don't test everything equally.
3. Pick the cheapest sufficient method (script > tool > browser) for each check.
4. Record findings with honest grades; exploitation stays in the next phase (approval-gated).
