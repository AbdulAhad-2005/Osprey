---
name: historical-url-discovery
description: "Discover endpoints not in the current crawl via waybackurls/gau historical URLs, then dedupe/filter and probe with httpx."
phases: [recon]
tags: [recon, urls, wayback]
---

# Historical URL Discovery

**When:** You need endpoints not visible in current crawl or DNS.

**Tools:** `waybackurls_discovery` or `gau_discovery`.

**Params:** `domain` or `url` depending on tool.

**Flags:** Use `additional_args` for any tool-specific filters (date ranges, include/exclude patterns). The platform does not restrict which flags you pass.

**Next step:** Deduplicate with `anew_data_processing` or filter with `uro_url_filtering`, then probe with httpx.

## gau vs waybackurls — different source coverage

`waybackurls` queries only the Wayback Machine's CDX API. `gau` ("get all URLs") queries Wayback
**plus** the Common Crawl dataset, AlienVault OTX, and (for the current provider version) urlscan
— broader coverage, but slower and noisier. Run `gau` when `waybackurls` alone looks thin; running
both and deduplicating is fine when time allows, since they don't fully overlap.

## Filter before probing — most of what comes back is noise

A raw historical-URL dump is dominated by static assets (`.js`, `.css`, `.png`, `.woff`) and
duplicate paths differing only by query string — probing all of it wastes httpx calls on
resources with no security relevance. Filter first: drop static-asset extensions, dedupe by
path-ignoring-query (`uro`'s default behavior), and prioritize anything with a query string,
an API-shaped path (`/api/`, `/v1/`, `/graphql`), or an admin/debug-shaped path
(`/admin`, `/debug`, `/.git`, `/backup`) before spending probe budget on the rest.

## The real value: dead endpoints and forgotten parameters

A historical URL that 404s on today's crawl isn't necessarily worthless — it can reveal an old
API version still technically routable, a removed-but-not-deleted admin panel, or (the highest-
value case) a **parameter name** the current app doesn't expose in its UI but the backend might
still accept. Any historical URL with a query string is a parameter-discovery lead — tag it
`injection_point_candidate` for `vuln/injection-testing` the same as a live-crawled parameter,
even if the exact URL it came from is now gone.
