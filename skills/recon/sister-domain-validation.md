---
name: sister-domain-validation
description: "Validate domain_hunter sister/affiliated-root candidates before trusting them, then promote the real ones into the graph."
phases: [recon]
tags: [recon, sister-domains, osint, validation]
---

# Validating sister / affiliated-root domains

`domain_hunter` finds OTHER root domains that may belong to the same
organisation (parents, subsidiaries, rebrands, self-hosted mail/DNS infra). When
an LLM is driving, its results are surfaced as **candidates** (observations with
`role=sister_candidate`), not confirmed sisters — they are leads for you to
judge, because affiliation is a human-level call that a scanner routinely gets
wrong (a third-party provider, a cited news site, an unrelated namesake).

Each candidate carries its evidence (`method` + `evidence`). Read it, then weigh:

- **Strong, usually real:** `reverse_whois` (same WHOIS registrant/org),
  `favicon_hash` (identical favicon), `tracker_pivot` (shared GA/GTM/pixel ID),
  `self_infra` (a mail/DNS host sharing the brand, e.g. `geoit.tv` for `geo.tv`),
  and `web_search` hits from the org's own Wikipedia infobox / official site.
- **Weak, verify first:** `site_scrape` outbound links and generic `web_mention`
  snippets — a homepage or search result mentioning a domain is not affiliation.

To validate when unsure: resolve it, open it and compare branding/content,
compare WHOIS registrant/org, check for a shared certificate SAN
(`crt_sh_query`) or the same analytics ID, or confirm a parent/subsidiary
relationship from an authoritative page. A shared brand token plus any one
strong signal is normally enough.

Promote the ones you confirm so later phases treat them as in-scope affiliates:

```
platform_graph_link(source=<seed>, target=<sister-domain>,
                    relation="affiliated_with", evidence="<why>", confidence="likely")
```

Leave the rest as candidates — don't delete them; a later signal may corroborate
one. Then feed a confirmed sister back into recon (resolve → probe → port-scan)
like any other in-scope root. This is guidance, not a gate: you decide what's
real.
