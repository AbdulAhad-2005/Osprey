---
name: dns-intelligence
description: "DNS intelligence with dnsenum/fierce when subdomain lists are thin or a zone transfer is suspected: nameservers, MX, zone transfer, and IP ranges."
phases: [recon]
tags: [recon, dns]
---

# DNS Intelligence

**When:** Subdomain lists are thin, zone transfer is suspected, or IP ranges are unknown.

**Tools:** `dnsenum_scan`, `fierce_scan`.

**Params:** `domain` (required for most modes).

**Flags:** Any valid dnsenum/fierce flags via `additional_args` (e.g. `-f`, `--dnsserver`, wordlist paths).

**Findings:** Nameservers, MX records, zone transfer results, discovered IP ranges.

## Zone transfer — try it against every nameserver, it costs nothing

A misconfigured DNS server allowing AXFR hands over the *entire* zone in one request — every
subdomain, no enumeration needed. Nearly always fails against a properly configured server, but
the check is free and occasionally hands over the whole recon phase in one shot:
```
dig axfr @<nameserver> <domain>
```
Try it against **every** nameserver for the domain (`dig NS <domain>` to enumerate them first) —
a domain with multiple NS records sometimes has one misconfigured secondary even when the
primary is locked down.

## SRV/TXT records — internal service hints on a public zone

`dig SRV _ldap._tcp.<domain>` / `_kerberos._tcp.<domain>` / `_sip._tcp.<domain>` reveal internal
service topology (AD domain controllers, VoIP infrastructure) even on an externally-facing zone,
since SRV records are sometimes replicated from internal DNS without the operator realizing it's
now public. `dig TXT <domain>` surfaces SPF/DKIM (mail infra, third-party SaaS integrations named
in `include:` clauses — a supply-chain/sister-domain lead) and occasionally leftover
verification tokens naming other services the domain owner uses.

## DNSSEC NSEC walking — zone enumeration without brute force

If the domain has DNSSEC enabled with NSEC (not NSEC3) records, walking the chain
(`dnsrecon -d <domain> -t zonewalk`, or manually via successive `dig` queries following each
NSEC record's "next domain name" field) enumerates every name in the zone alphabetically — a
complete subdomain list without any wordlist. Check `dig DNSKEY <domain>` first; NSEC3 (hashed)
zones don't allow this directly, but NSEC (unhashed) zones do.
