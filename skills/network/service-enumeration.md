---
name: service-enumeration
description: "Enumerate services on known-open ports with nmap_service_scan (-sV -sC) or nmap_custom_scan; parse port/protocol/version for downstream exploit planning."
phases: [network]
tags: [network, enumeration, nmap]
---

# Service Enumeration

**When:** Open ports are known (from rustscan/masscan/nmap syn).

**Default:** `nmap_service_scan` with `target` and optional `ports`.

**Flags:** `-sV -sC` are built in; add scripts or timing via `additional_args` (e.g. `--script vuln`, `-T4`).

**Custom:** `nmap_custom_scan` when you need a non-standard flag combination — set `flags` to the exact nmap argument string.

**Findings:** Parse as services with port/protocol/version for downstream exploit planning (future phases).

## NSE script categories — what each actually reveals

`-sC` runs nmap's `default` category — safe, broadly useful, but shallow. Reach for specific
categories via `additional_args` when the default isn't enough:
- `--script vuln` — checks for known CVEs against fingerprinted versions (the platform
  auto-runs this as a follow-up scan once ports/services are established — see
  `vuln/network-vuln-scan` — but re-running it manually with a narrower port list is useful when
  the auto-scan's port list was incomplete).
- `--script "smb-*"` — SMB-specific enumeration (signing, OS discovery, shares) when 445/139
  are open — deeper than plain `-sC`; see `network/smb-enumeration` for the SMB-specific tools.
- `--script "http-enum,http-title,http-headers"` — quick web fingerprinting when a port turns
  out to be HTTP-like but wasn't caught by recon's web tools (an unusual port serving a web UI).
- `--script "ssl-cert,ssl-enum-ciphers"` — TLS config/cert detail on any TLS port, feeding
  `vuln/tls-configuration`.

## Banner → CVE hinting

A confirmed version string (`OpenSSH 7.2p2`, `Apache httpd 2.4.7`, `vsftpd 2.3.4`) is a direct
`searchsploit_lookup` query, not just a data point — check every distinct version string against
it before moving on, especially on older/EOL-looking software (a strong signal worth flagging
even before a specific CVE is confirmed).

## Signal vs noise in `--script vuln` output

`vulners`/`vuln` category output is frequently version-string pattern-matching, not independent
verification — a hit means "this version has a CVE database entry," not "this specific
installation is vulnerable" (distros backport security fixes without bumping the visible version
string). Grade these as `inferred` (see `shared/finding-confidence`) until the `vuln`/`exploit`
phase actually attempts to confirm one.
