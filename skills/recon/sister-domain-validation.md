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
  `wikidata` (Wikidata's own subsidiary/parent-company record, chased to that
  entity's official website — curated structured data, not scraped text), and
  `web_search` hits from the org's own Wikipedia infobox / official site.
- **Weak, verify first:** `site_scrape` outbound links and generic `web_mention`
  snippets — a homepage or search result mentioning a domain is not affiliation.

To validate when unsure: resolve it, open it and compare branding/content,
compare WHOIS registrant/org, check for a shared certificate SAN
(`crt_sh_query`) or the same analytics ID, or confirm a parent/subsidiary
relationship from an authoritative page. A shared brand token plus any one
strong signal is normally enough.

Record the affiliation relationship for the ones you confirm, regardless of
whether you go on to test them:

```
platform_graph_link(source=<seed>, target=<sister-domain>,
                    relation="affiliated_with", evidence="<why>", confidence="likely")
```

Leave the rest as candidates — don't delete them; a later signal may corroborate
one.

**Confirmed-affiliated is not the same as in-scope.** The engagement's
RulesOfEngagement (and whatever authorization the operator actually has) are
per-target — a sister domain being operated by the same organisation doesn't
mean the SAME authorization covers it; a subsidiary can have its own security
ownership, or simply not be part of what was authorized. Don't silently start
running `subfinder`/`httpx`/`nmap`/etc. against a newly-confirmed sister under
the current engagement. Instead:

- If an interactive operator is attached, `ask_operator` which of: (a) start a
  **new engagement** for it (`platform_set_target(sister_domain)` — keeps its
  findings/RoE cleanly separate, the normal choice when it's a distinct
  authorization boundary), (b) work it under the **current** engagement (when
  the operator confirms the existing authorization already covers it), or (c)
  leave it as a reported lead only, not tested.
- With no operator attached (headless/spawned run, or the tool reports
  "unavailable"), default to (c) — report the confirmed affiliation and stop
  there. Don't guess scope on someone's behalf.

Once scope is actually settled (new engagement bound, or the operator said the
current one covers it), feed the sister back into recon like any other root:
resolve → probe → port-scan → widen again.
