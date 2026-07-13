# Sister Domain & Shared Hosting Discovery

**Source:** Dark-Moon samaa.tv campaign — caught defaced subdomains on shared hosting that checklist tools missed.

## When to use

- After subdomain enumeration and httpx probing
- When multiple subdomains resolve to the **same IP**
- Before concluding recon is complete

## Graph API

```
GET /api/v1/hybrid/graph/siblings?host=staging.example.com&engagement_id=
GET /api/v1/hybrid/graph/summary?engagement_id=
```

## Commander actions

1. Run `subdomain_discovery` workflow OR subfinder → httpx
2. Query graph for siblings on each live host
3. Probe sibling hostnames with httpx (may reveal defaced/staging sites)
4. Record findings with `confidence: confirmed` when HTTP 200 shows anomaly

## Tools

- `httpx_probe` with `additional_args: "-sc -title -td"`
- `dnsenum_scan` for IP range hints
- `fierce_scan` for adjacent DNS names

## Pivot hint

If graph returns 2+ siblings on one IP → **priority dispatch** to live_host_probing on all siblings.
