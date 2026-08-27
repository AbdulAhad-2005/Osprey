---
name: dns-intelligence
description: "DNS intelligence with dnsenum/fierce when subdomain lists are thin or a zone transfer is suspected: nameservers, MX, zone transfer, and IP ranges."
phase: recon
tags: [recon, dns]
---

# DNS Intelligence

**When:** Subdomain lists are thin, zone transfer is suspected, or IP ranges are unknown.

**Tools:** `dnsenum_scan`, `fierce_scan`.

**Params:** `domain` (required for most modes).

**Flags:** Any valid dnsenum/fierce flags via `additional_args` (e.g. `-f`, `--dnsserver`, wordlist paths).

**Findings:** Nameservers, MX records, zone transfer results, discovered IP ranges.
