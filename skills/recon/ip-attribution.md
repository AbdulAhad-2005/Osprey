---
name: ip-attribution
description: "Attribute CDN-fronted hosts to real origin IPs before network scanning, to avoid wasting scan budget on shared edge ranges."
phases: [recon]
tags: [recon, cdn, origin-ip]
---

# CDN / origin IP attribution

Use when evidence suggests a CDN or you need real IPs before network scanning.

## When

- httpx / headers show Cloudflare, Akamai, Fastly, CloudFront, etc.
- Host resolves only to known edge ranges / CDN CNAMEs
- You are about to port-scan and want to avoid wasting budget on edges

## Tool selection

| Need | Tool |
|------|------|
| Quick soft clues (dig+curl) | `cdn_origin_probe` |
| Full attribution with CIDR classification + verification | `origin_ip_attribution` |
| Bulk resolve hosts -> IPs/CNAMEs | `dnsx_resolve` |
| TLS SANs / issuer hints | `tlsx_inspect` |
| More hostnames from CT | `crt_sh_query` |

Long runs -> `platform_job_start`. Invented dig/curl via `platform_script`.

## Workflow

1. **Quick probe** — `cdn_origin_probe` for fast CDN detection + soft candidates
2. **Full attribution** — `origin_ip_attribution` for CIDR-based classification, MX/SPF/subdomain probing, header detection, and verification
3. **Supplement** — `dnsx_resolve` for bulk resolution of discovered subdomains, `tlsx_inspect` for cert SANs, `crt_sh_query` for more hostnames
4. **Verify** — `origin_ip_attribution` auto-verifies top candidates (direct IP + Host header). Manual check: `curl -k -H 'Host: <domain>' https://<candidate_ip>/`

## Signals (in order of reliability)

| Signal | What it means |
|--------|---------------|
| `cdn_ip_range:<provider>` | IP falls in published CDN CIDR range |
| `reverse_dns_cdn:<provider>` | rDNS hostname matches CDN pattern |
| `mx_server_ip` | IP is from MX record — likely origin infra |
| `spf_record_ip` | IP authorized in SPF record |
| `direct_subdomain` | Subdomain resolves outside CDN |
| `http_header:<provider>` | Response headers contain CDN signatures |
| `cert_issuer:<provider>` | TLS cert issued by CDN-specific issuer |

## Scoring

- `0.85+`: CDN edge IP (inside CIDR range or has CDN rDNS)
- `0.6`: MX server IP (likely origin infrastructure)
- `0.5`: SPF or direct subdomain IP (strong origin candidate)
- `0.2`: External IP, no strong signals (needs verification)
- Verified candidates get +0.2 confidence boost

## Do not

- Auto-chain every tool on every domain
- Treat MX/SPF IPs as proven origins without a live check
- Hardcode vendor playbooks — reason from the signal
- Claim CRITICAL from CDN presence alone
