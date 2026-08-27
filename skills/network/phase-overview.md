---
name: phase-overview
description: "Network phase overview: discover ports and services on hosts/IPs already in recon memory; fast port discovery first, then service enumeration."
phase: network
tags: [network, overview]
---

# Network Phase

Goal: discover ports and services on hosts/IPs already in recon memory — do not
re-enumerate subdomains here unless a new IP sibling appears.

**Instincts:**
1. Prefer IPs/hostnames already in the graph; group by shared IP when useful
2. Fast port discovery first (`naabu_port_scan`, else rustscan/masscan/nmap)
3. Version/scripts on interesting opens (`nmap_service_scan`) — not every port
4. Protocol follow-up only when evidence supports it (e.g. 445 → SMB tools)
5. If a scanner fails or times out: shrink scope / change tool — don’t “fix” by
   widening to full-range without asking the human

**Passive assist:** Shodan host/search results may suggest ports; still verify live
before SMB/web pivots.

**Assessing a CIDR/internal range instead of one host?** See `internal-subnet-sweep` —
compose `platform_fanout_assets` over the discovered host list rather than looping calls.

**Output:** Ports, services, and protocol observations into platform memory. Once ports/
services are established, the platform automatically runs a comprehensive network
vulnerability scan (`nmap --script vuln,vulners`, see `vuln/network-vuln-scan`) against
them right before the vuln phase starts — you do not need to trigger this yourself for
the primary target, though you can re-run it with different scope if the auto-scan's
port list was incomplete. (Note: "network" is not a separate auto-triggered conductor
phase — port/service work is part of the recon agent's own scope; this skill still
applies whenever a network-focused agent is spawned directly, e.g. via
`platform_spawn_agent(role='network')`.)
