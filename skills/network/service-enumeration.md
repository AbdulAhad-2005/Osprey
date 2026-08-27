---
name: service-enumeration
description: "Enumerate services on known-open ports with nmap_service_scan (-sV -sC) or nmap_custom_scan; parse port/protocol/version for downstream exploit planning."
phase: network
tags: [network, enumeration, nmap]
---

# Service Enumeration

**When:** Open ports are known (from rustscan/masscan/nmap syn).

**Default:** `nmap_service_scan` with `target` and optional `ports`.

**Flags:** `-sV -sC` are built in; add scripts or timing via `additional_args` (e.g. `--script vuln`, `-T4`).

**Custom:** `nmap_custom_scan` when you need a non-standard flag combination — set `flags` to the exact nmap argument string.

**Findings:** Parse as services with port/protocol/version for downstream exploit planning (future phases).
