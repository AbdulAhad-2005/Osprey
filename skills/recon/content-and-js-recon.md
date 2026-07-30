# Active recon — content, parameters, JavaScript & policy files

Goal: map the **live application attack surface** on hosts already confirmed up
(via httpx). Subdomain + port enumeration finds *hosts*; this finds the *paths,
parameters, endpoints and secrets* an attacker actually targets. Do this on every
live web host, prioritising crown jewels.

## Order of concerns (not rigid stages)

1. **Policy files first (cheap, high-signal)** — `well_known_probe` (url=). robots.txt
   Disallow entries, sitemap URLs, `security.txt`, and OIDC/SSO endpoints are free
   surface and often point straight at sensitive paths.
2. **Content discovery** — `feroxbuster_scan` (url=) as default (recursive, auto-tunes
   soft-404s). Use `ffuf_scan mode=directory` or `gobuster_scan` as alternates. Raise
   `depth=` / add `-x php,txt,bak,zip,sql` via additional_args on interesting hits.
   Chunk large wordlists with `platform_job_start`.
3. **Virtual hosts** — when many names share one IP (the graph shows `co_hosts`), run
   `ffuf_scan mode=vhost` to find hosts served only by Host header.
4. **JavaScript analysis** — `js_recon` (target=) on every live app host, and especially
   on SPA/API frameworks (React/Vue/Angular/Next). It downloads the page's JS and
   extracts endpoints/API paths, **hardcoded secrets** (API keys, tokens, JWTs, private
   keys) and **exposed cloud storage** (S3/GCS/Azure). This is where modern apps leak.
5. **Parameter discovery** — `arjun_scan` (url=) actively finds hidden parameters on a
   live endpoint. Passive parameters are also mined automatically from gau/wayback/katana
   URLs. Every parameter is an **injection-point candidate**.
6. **Deep crawl** — `katana_crawl` (url=) for JS-aware endpoint/form enumeration when you
   need breadth; it also mines query parameters from what it crawls.
7. **Email posture** — `email_security_probe` (domain=) once per domain: missing SPF/DMARC
   is a real, reportable spoofing exposure.

## Handoff to the vuln phase (do NOT test exploits here)

Findings tagged `injection_point_candidate` (parameters), `interesting_path`
(api/admin/graphql/…), `js-secret`, and `cloud-asset` are the ready-made attack
surface for later vulnerability analysis. Recon's job is to **find and record** them
with honest grades — not to exploit. A hardcoded secret is `observed` as *present* but
its validity is `unverified`: never claim HIGH/CRITICAL impact until you've confirmed it.

## Evidence discipline

- Content hits are OBSERVED (live HTTP response) — a `403`/`401` still means the path
  exists (tag `access_controlled`), it is not "nothing".
- JS endpoints are INFERRED leads until you probe them live.
- Secrets: exposure OBSERVED, impact UNVERIFIED — capped at MEDIUM until validated.
- Do not treat an SPA `index.html` served on `/api/*` as a real API — verify a JSON/auth response.
