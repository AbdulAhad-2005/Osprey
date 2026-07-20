# Recon Phase

Goal: map the external attack surface before intrusive network testing.

**Instincts (suggested order of concerns — not mandatory stages):**
1. Sister / seed scope (`domain_hunter`) when a domain is in play
2. Subdomain enumeration — more than one source if inventory looks thin
3. Live host probing **alongside** discovery (jobs/fanout), not only after
4. IP grouping / edge vs origin; ports + services on worth-time IPs
5. Historical URL / crawl / `platform_script` for app depth on high-value hosts
6. DNS / shared-infra pivots when the graph shows `co_hosts`

**Next step:** Prefer `platform_context` coverage gaps + thinking expansion cards + tree
over a fixed checklist — but do not treat “advisory” as “ignore.”

**Tool selection:** Pick the tool that fits the current finding. Any CLI flags via
`additional_args`. Failures → TRY NEXT / invent with script.

**Output:** Structured findings (subdomains, URLs, technologies) into platform memory.
