---
name: port-scan-strategy
description: "Port-scan strategy: prefer naabu_port_scan (top 1000), fall back to rustscan/masscan/nmap when missing or thin, and pass extra flags via additional_args."
phases: [network]
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

## Speed vs coverage tradeoff

Top-1000/top-ports covers the overwhelming majority of real services in minutes; full `1-65535`
finds what a narrow scan misses (a service moved off its default port specifically to dodge quick
scans — a real, if uncommon, pattern) but costs orders of magnitude more time. Escalate to full
range when: the host looks otherwise interesting (in-scope, live, other signals) but top-ports
found little; a specific finding hints at a non-standard port (an app config leak referencing
`:8443`, a Shodan result showing a port outside top-1000); or the engagement explicitly asks for
full coverage. Don't default to full-range on every host — it doesn't scale across a large asset
list and mostly re-confirms what top-ports already found.

## Timing and evasion

`-T4` (aggressive) is the default assumption for an authorized, non-stealth engagement — faster,
and a target that can't handle it is itself worth knowing. Drop to `-T2`/`-T3` when a host shows
signs of struggling (timeouts, connection resets) rather than assuming the scan itself is broken.
`-Pn` skips the host-discovery ping — required when a host blocks ICMP but is otherwise reachable
(don't conclude "host down" from a failed ping alone). Fragmentation (`-f`) and decoy scanning
(`-D`) exist in nmap but rarely matter on an authorized internal/external pentest where evasion
isn't the point — reach for them only if the engagement specifically tests detection evasion (see
`defense-evasion`), not as a default.

## Version/OS detection feeds exploit planning

A bare port list ("445 open") is much less actionable than a version-fingerprinted one ("445 open,
Samba 4.3.11 — CVE-2017-7494 candidate"). `-sV` (part of `nmap_service_scan`'s defaults) and `-O`
(OS detection, needs raw-socket privilege — the container has `cap_net_raw` via `setcap`, so this
works despite running unprivileged) both feed directly into `searchsploit_lookup` and the
`vuln`/`exploit` phases downstream — treat a fast port sweep as step one, not the deliverable.

## Context-dependent scanning

Read CURRENT SITUATION before each tool. Do not run SMB tools without 139/445 in evidence.
Use targeted port lists from findings when a wide scan already failed or timed out.
The container is unprivileged — prefer `-sT` / `--unprivileged` over raw SYN, and `-Pn` when a host blocks ping.
Full `1-65535` is allowed and runs without a gate — prefer top-ports/1-1000 first for speed, escalate to full when it's worth it. Honor an explicit operator "no full scan" constraint.
