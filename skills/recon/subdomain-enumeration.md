---
name: subdomain-enumeration
description: "Subdomain enumeration for a root domain: subfinder by default, pivoting to amass/dnsenum/crt.sh, then takeover checks on interesting names."
phases: [recon]
tags: [recon, subdomains]
---

# Subdomain Enumeration

**When:** Start of recon on a single root domain.

**Default:** `subfinder_scan` with `domain` param.

**Pivot rules:**
- Few results → try `amass_scan` with `additional_args: "-passive"` or `fierce_scan`
- Need brute force → `amass_scan` with `additional_args: "-brute -w /path/to/wordlist"` (any valid amass flags)
- DNS-focused → `dnsenum_scan`
- CT gap-fill → `crt_sh_query`
- Passive internet view → `shodan_search` with `domain=` or `query=hostname:…` / `ssl:…`
- After a solid host list → `subdomain_takeover_check` (`mode=list`) on interesting names

**Params:** `domain` (required for most). Pass any extra flags in `additional_args` — not limited to documented examples.

**Do not:** Run intrusive scans before passive sources are exhausted unless engagement rules allow it.

## Wildcard DNS — check before trusting brute-force hits

A wildcard DNS record (`*.example.com` resolves to something) makes every brute-forced/guessed
name "resolve," producing false subdomains that were never real. Check for it before running or
trusting brute-force results: resolve an obviously-nonexistent name
(`definitely-not-real-$(random).example.com`) — if it resolves, the domain has a wildcard, and
brute-force/permutation results need the wildcard's IP filtered out (or a tool with wildcard
detection, like `massdns`/`puredns`, instead of raw brute force) before any hit is trusted.

## Permutation — beyond pure enumeration

Once you have a real subdomain list, generate plausible siblings from naming patterns instead of
only collecting what passive sources already indexed: `api-eu1.` → try `api-us1.`/`api-ap1.`;
`app-stage.` → try `app-staging.`/`app-stage2.`; numbered hosts (`db-01.`) → try adjacent numbers.
This finds infrastructure that was never linked anywhere public and so never made it into
crt.sh/subfinder's sources — see `shared/attack-surface-instincts` for the full pattern-inference
approach; it applies here directly.

## When brute force is/isn't worth it

Brute-force wordlists (`amass -brute -w <wordlist>`) are slow and noisy relative to their hit
rate against a well-indexed target — passive sources (subfinder/crt.sh/amass passive) plus
permutation usually find more, faster. Reach for brute force specifically when: passive sources
returned very few names for a domain that's clearly larger (an enterprise with 3 known
subdomains is almost certainly under-enumerated), or a permutation pattern didn't confirm the
existence of a suspected internal naming scheme and you need to search harder for it.
