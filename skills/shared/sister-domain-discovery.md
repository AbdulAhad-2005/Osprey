---
name: sister-domain-discovery
description: "Discover affiliated root domains (subsidiaries, sibling brands, shared infrastructure) and staging hosts the checklist misses, widening scope beyond the seed."
phase: shared
tags: [recon, sister-domains, scope]
---

# Sister Domain & Shared Hosting Discovery

Finds domains the checklist misses: affiliated **root** domains (subsidiaries,
sibling brands, shared infra) and defaced/staging subdomains on shared hosting.

## When to use
- Early in recon, to widen the domain scope beyond the seed
- After subdomain enumeration and httpx probing
- When multiple subdomains resolve to the **same IP**
- Before concluding recon is complete

## Actions
1. Run `domain_hunter` on the seed root domain to surface affiliated/sister domains
2. Run subfinder → httpx to map live hosts on the seed (and on any confirmed sister domains)
3. Query the engagement graph for siblings on each live host
4. Probe sibling hostnames with httpx (may reveal defaced/staging sites)
5. Record findings with high confidence when an HTTP 200 shows an anomaly

## Tools
- `domain_hunter` — affiliated **root** domains via OSINT (certs, DNS/ASN, WHOIS,
  Wikidata, TLD/pattern variants). Each hit carries method, confidence, and live
  status; results land in the graph. Free by default; raise `confidence_min` to
  `medium`/`high` to cut noise. Not a subdomain tool — pair it with subfinder.
- `httpx_probe` with `additional_args: "-sc -title -td"`
- `dnsenum_scan` for IP range hints
- `fierce_scan` for adjacent DNS names

## Pivot hint
- Soft gaps `sister_unenumerated` / `shared_infra_unprobed` guide follow-ups — they are advisory.
- Optional batch: `platform_fanout(action="enumerate_sisters")` with dry_run first; never silent after domain_hunter.
- Feed high-confidence live `domain_hunter` domains into subdomain enumeration + probing when gaps say so.
- If the graph returns 2+ siblings on one IP (`co_hosts`) → consider live-host probing on unprobed siblings.
