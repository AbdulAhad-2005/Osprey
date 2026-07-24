# Recon Phase

Goal: map the external attack surface before intrusive network testing.

**Instincts (suggested order of concerns — not mandatory stages):**
1. Sister / seed scope (`domain_hunter`) when a domain is in play
2. Subdomain enumeration — more than one source if inventory looks thin
3. Passive internet OSINT (`shodan_search`) when an API key is available — widen without scanning
4. Live host probing **alongside** discovery (jobs/fanout), not only after
5. IP grouping / edge vs origin; ports + services on worth-time IPs (`naabu_port_scan` → nmap)
6. Dangling CNAME / takeover fingerprints on the host list (`subdomain_takeover_check`)
7. Historical URL / crawl / `platform_script` for app depth on high-value hosts
8. DNS / shared-infra pivots when the graph shows `co_hosts`
9. Technology identification (`whatweb_scan` / `tech_stack_analyze`) on live hosts — informs targeted vuln research

**Next step:** Prefer `platform_context` coverage gaps + thinking expansion cards + tree
over a fixed checklist — but do not treat "advisory" as "ignore."

**Tool selection:** Pick the tool that fits the current finding. Any CLI flags via
`additional_args`. Failures → invent another probe (script, job, different binary).

**Output:** Structured findings (subdomains, URLs, technologies) into platform memory.

**Evidence discipline:** Passive/API leads ≠ proven impact. Confirm live before HIGH claims.
