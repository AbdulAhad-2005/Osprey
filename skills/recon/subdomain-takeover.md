---
name: subdomain-takeover
description: "Spot dangling CNAMEs pointing at unclaimed SaaS across a subdomain/host list with subdomain_takeover_check."
phases: [recon]
tags: [recon, takeover]
---

# Subdomain Takeover Checks

**When:** You have a subdomain / host list (from `subfinder_scan`, `amass_scan`,
`crt_sh_query`, memory) and want to spot dangling CNAMEs to unclaimed SaaS.

**Tool:** `subdomain_takeover_check`

**Modes:**
- `mode=single` + `target=host` — one host
- `mode=list` + `subdomains=` newline/comma list — preferred after enum
- Soft cap `max_hosts` (default 50) — chunk large inventories with jobs/fanout

## How to think

- Fingerprint match (`vulnerable` tag) = strong **observed signal**, not automatic
  proof you can claim the service. Confirm claimability before high severity.
- `potential` = SaaS-looking CNAME + empty/404 — verify manually; do not flood the
  report with unvalidated CRITICAL.
- No CNAME ≠ “safe forever” — other takeover classes exist; invent probes if the
  graph still shows interesting dangling DNS.

## Suggested flow (reorder freely)

1. Enumerate subs → store in memory
2. Optionally resolve CNAMEs with `dnsx_resolve`
3. `subdomain_takeover_check` on the interesting / all-new hosts
4. For hits: deepen with HTTP evidence, then grade honestly

**Do not:** Re-run discover-style subfinder inside this tool — you already have
typed subdomain tools. Pass the list you care about.
