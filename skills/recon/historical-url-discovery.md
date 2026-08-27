---
name: historical-url-discovery
description: "Discover endpoints not in the current crawl via waybackurls/gau historical URLs, then dedupe/filter and probe with httpx."
phase: recon
tags: [recon, urls, wayback]
---

# Historical URL Discovery

**When:** You need endpoints not visible in current crawl or DNS.

**Tools:** `waybackurls_discovery` or `gau_discovery`.

**Params:** `domain` or `url` depending on tool.

**Flags:** Use `additional_args` for any tool-specific filters (date ranges, include/exclude patterns). The platform does not restrict which flags you pass.

**Next step:** Deduplicate with `anew_data_processing` or filter with `uro_url_filtering`, then probe with httpx.
