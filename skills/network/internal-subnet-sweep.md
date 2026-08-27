---
name: internal-subnet-sweep
description: "Assess an internal CIDR by composing existing primitives (platform_fanout_assets plus CIDR-capable scanners); no dedicated subnet-scan tool is needed."
phase: network
tags: [network, cidr, internal]
---

# Internal-network / subnet sweep

Assessing an internal CIDR (not a single host) composes existing primitives — there is no
separate "subnet scan" tool and none is needed. `platform_fanout_assets` already does
bounded-concurrency, dry-run-gated execution of one tool across an explicit host list; the
CIDR-capable scanners (`nmap_syn_scan`, `masscan_high_speed`, `naabu_port_scan`) already accept
a CIDR target directly.

## The chain

1. **Discover live hosts in the CIDR.** `nmap_syn_scan`/`masscan_high_speed`/`naabu_port_scan`
   against the CIDR (e.g. `10.0.0.0/24`) — these already accept a CIDR as `target`. This gives
   you the host list, not yet per-host port/service detail.
2. **Per-host service scan.** `platform_fanout_assets` with `tool_name="nmap_service_scan"` and
   `assets=<the discovered host list>`. Always `dry_run` first to confirm the list before
   `confirm=true` executes it. This establishes ports/services per host — the same thing a
   single-host recon phase would do, just fanned out.
3. **Per-host comprehensive vuln scan.** `platform_fanout_assets` with
   `tool_name="nmap_custom_scan"`, `additional_args='-Pn -sV --script "vuln,vulners" -p <ports>'`
   (see `network-vuln-scan`) across the same host list. One category-driven scan per host —
   no per-host script-set decisions needed, nmap already adapts to whatever that host has open.
4. **Exploit correlation.** `searchsploit_lookup` against the CVEs step 3 surfaced.

## Why fanout, not a loop

`platform_fanout_assets` already handles what a hand-rolled loop would get wrong: bounded
concurrency (reuses the platform's job concurrency cap, so this doesn't open more simultaneous
kali-tools execs than anything else running), de-duplication of the asset list, and an explicit
dry-run preview before anything executes. Looping tool calls yourself serializes unnecessarily
and skips the preview step.

## Scope discipline

- `max_assets` on fanout defaults to 25 — an internal /24 has up to 254 hosts. Scope the sweep
  (a known-live subset, a specific range) rather than assuming the full subnet fits one fanout
  call; chain multiple fanout calls over sub-ranges if the engagement genuinely needs full
  coverage.
- Internal ranges (RFC1918) still need the same authorization discipline as any other target —
  confirm the CIDR is in scope before sweeping it, the same way you would a single host.

## Do not

- Loop `nmap_custom_scan` calls yourself host-by-host — use `platform_fanout_assets`, it already
  solves concurrency/dedup/dry-run.
- Skip straight to the vuln scan (step 3) without the per-host service scan (step 2) — `vulners`'
  CPE matching needs `-sV` service/version data to match against; without it the scan finds
  nothing useful.
- Assume every host in a discovered range is in scope just because it responded to discovery —
  discovery finds what's alive, not what's authorized.
