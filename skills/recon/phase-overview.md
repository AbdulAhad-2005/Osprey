---
name: recon-overview
description: "Recon phase overview: map the external attack surface before intrusive testing, adapting to the target kind (domain, IP, IPv6, CIDR, or host:port)."
phases: [recon]
tags: [recon, overview]
---

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

**Instincts (for a domain target — the order can flex with what the target gives you,
but every stage's work is required, not optional to skip):**
1. Sister / seed scope (`domain_hunter`) when a domain is in play
2. Subdomain enumeration EVERY way — subfinder + crt.sh + amass + domain_hunter + cert SANs;
   more than one source if inventory looks thin
3. Passive internet OSINT (`shodan_search`) when an API key is available — widen without scanning
4. Resolve ALL discovered names to IPs (`dnsx_resolve`); live host probing **alongside**
   discovery (jobs/fanout), not only after
5. IP grouping / edge vs origin — **attempt CDN/WAF-origin bypass on every fronted host**
   (direct-to-origin probes, DNS history, TLS, header analysis, `origin_ip_attribution`);
   this is not optional for a CDN-fronted target, it's part of the recon job
6. Ports + services in MULTIPLE scan kinds on worth-time IPs (`naabu_port_scan` top-1000,
   SYN, rustscan, masscan variants) → version/scripts (`nmap_service_scan`) on everything open
7. Dangling CNAME / takeover fingerprints on the host list (`subdomain_takeover_check`)
8. Historical URL / crawl / `platform_script` for app depth on high-value hosts (httpx live,
   gau/wayback, js_recon, katana)
9. DNS / shared-infra pivots when the graph shows `co_hosts`
10. Technology identification (`whatweb_scan` / `tech_stack_analyze`) on live hosts — informs
    targeted vuln research

**Asset-discovery pivots (beyond subfinder/crt.sh basics;
loaded unconditionally, every recon agent gets this):**
- **Iterate to convergence, don't run each source once.** CT (`crt_sh_query`) → TLS
  SAN pivot (`tlsx_inspect`) → resolve (`dnsx_resolve`) → ASN/IP-range sweep
  (`asn_enum`) → back to CT on any new org/domain found → repeat until a full pass
  adds nothing new. One pass through each tool is not "done."
- **Read every SAN on a cert, not just the hostname you queried.** `tlsx_inspect`
  returns the full SAN list — pull ALL of them as new seeds, including ones for
  names you never enumerated. A wildcard or multi-domain cert is a free subdomain
  list. Internal-looking SANs (`*.internal`, `*.svc.cluster.local`, `localhost`,
  staging/dev/admin prefixes) on a public cert are high-signal — flag them.
- **Cert-fingerprint pivoting.** Two hosts serving the identical TLS cert
  (same SHA-256 fingerprint) are the same origin infra even with unrelated
  hostnames — cross-check via `shodan_search`/`shodan_host_info` for other IPs
  presenting that fingerprint, especially useful for a CDN-fronted apex where
  the origin's own cert leaks its real IP.
- **Infer naming conventions instead of only brute-forcing.** If discovered names
  show a pattern (`api-eu1.`, `api-us1.`, `app-stage.`, `db-01.`), generate the
  missing siblings from that pattern (`api-ap1.`, `app-stage2.`, `db-02.`) and
  resolve them — targeted guesses beat a blind wordlist.
- **Vhost differentials.** The same IP can serve different applications per
  Host header. Once you have a live IP, probe it with each discovered hostname
  as the Host header (httpx/curl via `additional_args` or `platform_script`) —
  don't assume one IP is one app just because one hostname resolved there.
- **Classify what you find by function**, not just by name: app / API / auth /
  admin / CI-CD / VCS / observability / mail / storage. This drives where to
  spend depth later (admin/CI-CD/VCS hosts are usually worth more than a
  marketing subdomain) — it's a priority signal, not a filter.
- **Recon-specific false positives to not over-claim:** a CDN/edge IP is not the
  org's infrastructure; a shared-hosting neighbor on the same IP is not
  necessarily the same org; a historical/passive-DNS hit may point at
  reassigned infra that's no longer theirs; a wildcard cert doesn't mean every
  possible subdomain actually resolves. Confirm live + attributed before
  recording as a real asset, same evidence discipline as everywhere else.

**Breadth before depth:** Probe EVERY live host at least shallowly (httpx + fast port
sweep) before deep-diving ANY single one — the win is usually a host you never looked at,
not a fifth tool run on one you already own. Keep enumerating until a full pass adds no
new assets; every new name/SAN/PTR/CNAME is a fresh seed. Offload the host inventory to
the graph so a full context window never forces you to stop. See `asset-discovery-breadth`.

**Next step:** Check `platform_pipeline`'s phase-readiness signal and `platform_context`
for what's already known — but do not treat "advisory" as "ignore."

**Tool selection:** Pick the tool that fits the current finding. Any CLI flags via
`additional_args`. Failures → invent another probe (script, job, different binary).

**Output:** Structured findings (subdomains, URLs, technologies) into platform memory.

**Evidence discipline:** Passive/API leads ≠ proven impact. Confirm live before HIGH claims.
