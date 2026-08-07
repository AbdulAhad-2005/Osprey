# Recon Phase

Goal: map the external attack surface before intrusive network testing.

**Adapt to the target kind** (shown in the session header as `[kind: …]`). The engagement can be
bound to a domain, IP, IPv6, CIDR, or host:port — not just a domain:
- **domain** — full recon below (sisters → subdomains → live hosts → …).
- **ip / ipv6** — no domain to enumerate: skip subdomain enum; go to port/service scanning, then
  web/vuln. `dnsx_reverse` (PTR) and `asn_enum` still widen context; a reverse-DNS hostname can
  reopen domain recon.
- **cidr** — sweep the range for live hosts/ports first (naabu/masscan/nmap across it), then
  service/vuln scan what's up. No subdomain enum.
- **host:port (scope shown as `scope: port N`)** — the user scoped to one service: direct network/
  web tools at that host:port; don't spend the scan on other ports unless scope is widened.

**Instincts (for a domain target — suggested order of concerns, not mandatory stages):**
1. Sister / seed scope (`domain_hunter`) when a domain is in play
2. Subdomain enumeration — more than one source if inventory looks thin
3. Passive internet OSINT (`shodan_search`) when an API key is available — widen without scanning
4. Live host probing **alongside** discovery (jobs/fanout), not only after
5. IP grouping / edge vs origin; ports + services on worth-time IPs (`naabu_port_scan` → nmap)
6. Dangling CNAME / takeover fingerprints on the host list (`subdomain_takeover_check`)
7. Historical URL / crawl / `platform_script` for app depth on high-value hosts
8. DNS / shared-infra pivots when the graph shows `co_hosts`
9. Technology identification (`whatweb_scan` / `tech_stack_analyze`) on live hosts — informs targeted vuln research

**Breadth before depth:** Probe EVERY live host at least shallowly (httpx + fast port
sweep) before deep-diving ANY single one — the win is usually a host you never looked at,
not a fifth tool run on one you already own. Keep enumerating until a full pass adds no
new assets; every new name/SAN/PTR/CNAME is a fresh seed. Offload the host inventory to
the graph so a full context window never forces you to stop. See `asset-discovery-breadth`.

**Next step:** Prefer `platform_context` coverage gaps + thinking expansion cards + tree
over a fixed checklist — but do not treat "advisory" as "ignore."

**Tool selection:** Pick the tool that fits the current finding. Any CLI flags via
`additional_args`. Failures → invent another probe (script, job, different binary).

**Output:** Structured findings (subdomains, URLs, technologies) into platform memory.

**Evidence discipline:** Passive/API leads ≠ proven impact. Confirm live before HIGH claims.
