---
name: passive-osint-shodan
description: "Passive internet-wide ports, banners, and hostnames via Shodan (shodan_search, shodan_host_info) without scanning; authorized targets only."
phase: recon
tags: [recon, shodan, passive]
---

# Passive OSINT — Shodan

**When:** After (or alongside) subdomain/DNS inventory, when you want internet-wide
passive ports, banners, and hostnames without scanning yet. Authorized targets only.

**Tools:**
- `shodan_search` — query Shodan (`query=` or `domain=` → `hostname:<domain>`)
- `shodan_host_info` — deepen one IP (`ip=` / `target=`)

**Needs:** `SHODAN_API_KEY` in `.env` (forwarded into Kali). If the tool says key
missing, stop retrying the same call — fix env / restart, then continue.

## Query instincts (ideas, not scripts)

Use Shodan’s query language freely via `query=`:
- `hostname:example.com` / `ssl:example.com`
- `org:"Org Name"` when WHOIS/org is known
- `ip:1.2.3.4` or product/port filters when evidence supports them
- Tighten with `limit=` when results are noisy

## How to use results

- Shodan ports/hostnames are **passive leads** — verify live with `httpx_probe`,
  `naabu_port_scan`, or `nmap_*` before treating as confirmed open services.
- CVE / vuln tags from `shodan_host_info` are **unverified leads** — do not claim
  HIGH/CRITICAL from Shodan tags alone.
- Prefer writing interesting correlations into memory (`platform_graph_link` /
  `platform_think`) when passive data suggests shared infra.

## Pivot

Thin Shodan → broaden query or fall back to active enum. Rich Shodan → resolve,
group IPs, then live probe / targeted ports — not full-range sweeps by default.
