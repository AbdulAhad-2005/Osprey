# CDN / origin clues (flexible — not a checklist)

Use when evidence suggests a CDN or you need real IPs before network scanning.
There is **no required order**. Skip steps that do not fit the engagement.

## When

- httpx / headers show Cloudflare, Akamai, Fastly, CloudFront, etc.
- Host resolves only to known edge ranges / CDN CNAMEs
- You are about to port-scan and want to avoid wasting budget on edges

## Tools (pick what you need)

| Need | Tool |
|------|------|
| Bulk resolve hosts → IPs/CNAMEs | `dnsx_resolve` |
| TLS SANs / issuer hints | `tlsx_inspect` |
| More hostnames from CT | `crt_sh_query` |
| Soft CDN + origin *candidates* | `cdn_origin_probe` |

Long runs → `platform_job_start`. Invent dig/curl via `platform_script` if a wrapper is missing.

## Thinking

1. SIGNAL — quote CDN header/CNAME/edge IP
2. CONFIRM — second probe (tlsx / origin probe / direct subdomain)
3. GRADE — origin candidates are usually `inferred` until you prove a live service on that IP
4. DEEPEN — prefer scanning **origin candidates**, not edge IPs labeled CDN
5. Do not claim CRITICAL from CDN presence alone

## Do not

- Auto-chain every tool on every domain
- Treat MX/SPF IPs as proven origins without a live check
- Hardcode vendor playbooks — reason from the signal
