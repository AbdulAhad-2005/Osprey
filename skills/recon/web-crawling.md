---
name: web-crawling
description: "Deeper endpoint discovery on a live URL via hakrawler_crawl (forms, JS routes, depth-limited spider), staying within engagement scope."
phases: [recon]
tags: [recon, crawl]
---

# Web Crawling

**When:** A live URL needs deeper endpoint discovery (forms, JS routes, depth-limited spider).

**Default:** `hakrawler_crawl` on a confirmed live URL.

**Flags:** Depth, scope, and thread tuning via `additional_args` — use your knowledge of hakrawler flags freely.

**Scope:** Stay within engagement target scope. Do not crawl out-of-scope domains even if linked.

## Seed the crawl, don't just point it at the root

`robots.txt` and `sitemap.xml` frequently list paths a link-following crawler would never reach
on its own (disallowed-but-not-actually-protected admin paths, an old sitemap referencing
deprecated-but-still-live endpoints) — fetch both before crawling and feed anything interesting
in as explicit seed URLs, not just the bare root.

## The SPA blind spot

`hakrawler` (and most link-following crawlers) parses static HTML for `<a href>`/`<script src>` —
it cannot execute JavaScript. A single-page app whose entire route table is built client-side
(React Router, Vue Router) looks like ONE page to a static crawler regardless of how many real
routes exist. Signal: a crawl returning only 1-3 URLs from an app that clearly has more surface
(check the page title, look for `#/` or pushState-style URLs) means switch to `browser_flow` or
`browser_scrape` (real browser rendering) instead of concluding the crawl was thorough — see
`web/browser-automation`. `javascript-recon`'s JS-bundle mining is the other half of this: an
SPA's route table is usually readable directly out of its bundled JS even without executing it.

## Feed discoveries back in

Forms, JS-referenced API routes, and any parameter-bearing URL the crawl turns up are exactly
the `injection_point_candidate` seeds `vuln/injection-testing` expects — tag them as such rather
than letting them sit as generic "found URL" findings.
