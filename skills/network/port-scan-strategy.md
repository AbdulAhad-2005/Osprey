---
name: port-scan-strategy
description: "Port-scan strategy: prefer naabu_port_scan (top 1000), fall back to rustscan/masscan/nmap when missing or thin, and pass extra flags via additional_args."
phase: network
tags: [network, port-scan]
---

# Port Scan Strategy

**When:** You have a host IP or hostname from recon findings.

**Fast discovery (preferred):** `naabu_port_scan` — default `top_ports=1000`. Pass
explicit `ports=` when you already know a shortlist. Extra flags via `additional_args`.

**Alternatives:** `rustscan_fast_scan` or `masscan_high_speed` when naabu is missing
or results look thin — fallback, don’t stop.

**Stealth / full TCP:** `nmap_syn_scan` with `ports`, `timing`, and any nmap flags in
`additional_args` or `flags` for custom scans.

**Custom nmap:** `nmap_custom_scan` — put the full flag string in `flags` or `additional_args`.

**Passive preview:** `shodan_host_info` / `shodan_search` can suggest ports before you
scan — still verify live.

**Pivot:** Open 445/139 → SMB enumeration task. Open 80/443 → return to web recon if not done.

## Context-dependent scanning
Read CURRENT SITUATION before each tool. Do not run SMB tools without 139/445 in evidence.
Use targeted port lists from findings when a wide scan already failed or timed out.
The container is unprivileged — prefer `-sT` / `--unprivileged` over raw SYN, and `-Pn` when a host blocks ping.
Never start full `1-65535` on your own — ask the human first.
