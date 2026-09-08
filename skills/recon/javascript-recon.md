---
name: javascript-recon
description: "Mine bundled and inline JavaScript for API routes, secrets, and cloud assets with js_recon; run on every live app host, especially SPAs where the real surface hides."
phases: [recon]
tags: [recon, javascript, secrets]
---

# JavaScript Recon — endpoints, secrets & cloud assets

Modern apps ship their attack surface in JavaScript. A SPA's `index.html` is nearly empty;
the real API routes, feature flags, admin paths, and too often **hardcoded credentials** live
in bundled JS. `js_recon` (target= a page or a `.js` URL) downloads the page, discovers every
referenced and inline script, and mines them for three things. Run it on **every live app
host**, and always on React/Vue/Angular/Next/Svelte targets — that is where leaks hide.

## What `js_recon` extracts

1. **Endpoints / API paths** — LinkFinder-style relative + absolute references. Security-relevant
   ones (`/api`, `/admin`, `/graphql`, `/internal`, `/upload`, tokens in paths) are ranked first.
2. **Hardcoded secrets** — specific patterns before generic: AWS access/secret keys, SendGrid,
   Slack tokens/webhooks, Google/Firebase keys, Stripe, GitHub tokens, private keys, and JWTs.
   Obvious placeholders (`example`, `your_key`, `xxxx`, `changeme`, `test_key`) are filtered out.
3. **Exposed cloud storage** — S3 (virtual-host, path-style, and `s3://`), GCS buckets, and Azure
   blob containers referenced in the code.

## Workflow

1. **Seed from live hosts.** For each `httpx`-confirmed app host, run `js_recon` (target= the
   app URL). It auto-discovers `<script src=…>` and inline scripts — you do not list them yourself.
2. **Go deeper on bundles.** If the app loads a big vendor/app bundle (`main.[hash].js`,
   `app.js`, `chunk-*.js`), point `js_recon` straight at that URL — hash-named chunks often hold
   the routes the entry page hides.
3. **Turn endpoints into surface.** Each discovered endpoint is an INFERRED lead. Probe the
   interesting ones live (`httpx_probe`, or a `platform_script` curl) to confirm they exist and
   see auth behaviour. Confirmed `/api|/admin|/graphql` paths become `interesting_path` leads and
   feed content/parameter discovery (`arjun_scan`, `ffuf_scan`).
4. **Triage secrets by validity, not by presence.** A matched key is `observed` as *present* in
   the source; its *validity* is `unverified`. Never claim HIGH/CRITICAL from a regex hit alone —
   it may be a public/publishable key (e.g. a Stripe/Firebase **publishable** key is designed to
   ship client-side) or a rotated/dead credential. Note the exposure, mark it a `js-secret` lead,
   and hand validation to the vuln/exploitation phase.
5. **Record cloud assets.** S3/GCS/Azure references are `cloud-asset` leads — the bucket may be
   public-listable or writable, but that is a *later* test. Recon records the reference only.

## Pair with the crawler

`js_recon` reads the JS a page *serves*; `katana_crawl` follows links + JS to enumerate the app's
route graph. Use `js_recon` for secret/endpoint mining on the bundles `katana` discovers — they
complement each other (crawl for breadth, js_recon for depth on each script).

## Evidence discipline

- Endpoints from JS are INFERRED until probed live — a string in code is not a working route.
- A JS `index.html` served on `/api/*` is an SPA fallback, not an API — verify a JSON/auth response.
- Secrets: exposure OBSERVED, impact UNVERIFIED — capped at MEDIUM until a live check proves the
  credential works. Distinguish **secret** keys from **publishable** ones before you rate severity.
- Cloud buckets: the *reference* is observed; listability/writability is a separate, later test.

## Handoff (do NOT exploit here)

Leads land tagged `interesting_path`, `injection_point_candidate`, `js-secret`, and `cloud-asset`.
Recon's job is to find and record them with honest grades. Validation and exploitation belong to
the vulnerability phase — see the vuln skills.
