---
name: web-crawling
description: "Deeper endpoint discovery on a live URL via hakrawler_crawl (forms, JS routes, depth-limited spider), staying within engagement scope."
phase: recon
tags: [recon, crawl]
---

# Web Crawling

**When:** A live URL needs deeper endpoint discovery (forms, JS routes, depth-limited spider).

**Default:** `hakrawler_crawl` on a confirmed live URL.

**Flags:** Depth, scope, and thread tuning via `additional_args` — use your knowledge of hakrawler flags freely.

**Scope:** Stay within engagement target scope. Do not crawl out-of-scope domains even if linked.
