# Technology Identification

**When:** After live host probing, or when you need to understand the target's technology stack for security assessment.

**Goal:** Identify CMS, frameworks, web servers, JavaScript libraries, analytics, CDNs, and programming languages to guide targeted security testing.

## Tools (pick what fits)

| Tool | Speed | Depth | Best For |
|------|-------|-------|----------|
| `whatweb_scan` | Fast | 1800+ plugins | CMS, frameworks, JS libs, servers |
| `wappalyzer_scan` | Medium | Categorized | Version detection, categorized stack |
| `tech_stack_analyze` | Slow | All-in-one | Comprehensive report with security assessment |
| `httpx_probe` (with `-td`) | Fast | Basic | Quick tech check during host probing |

**Default:** `whatweb_scan` for initial fingerprinting. Use `tech_stack_analyze` for comprehensive assessment.

## Workflow

1. **Initial fingerprint** — `whatweb_scan(target="https://target.com")` for fast detection
2. **Deep analysis** — `tech_stack_analyze(target="https://target.com")` for full stack + security assessment
3. **Cross-validate** — `wappalyzer_scan` to confirm findings from WhatWeb
4. **Act on signals** — Use `tech_dispatch.yaml` signals for follow-up probes

## What to look for

### CMS Detection
- **WordPress** → probe `/wp-json/wp/v2/users`, check plugins/themes, run `wpscan_analyze`
- **Joomla** → probe `/administrator/`, check for known Joomla CVEs
- **Drupal** → check `/CHANGELOG.txt`, test for Drupalgeddon variants
- **Laravel** → check `/.env` exposure, test Ignition RCE

### Server Detection
- **Apache** → directory listing, `.htaccess` exposure, version CVEs
- **Nginx** → alias traversal, CRLF injection, version CVEs
- **IIS** → WebDAV, `web.config` exposure, old version CVEs

### Framework Detection
- **Express/Node.js** → prototype pollution, debug endpoints
- **Django/Flask** → debug mode, `__debug__` endpoints
- **ASP.NET** → ViewState validation, debug mode

### JavaScript Libraries
- **jQuery** → known XSS versions (< 3.5.0)
- **Angular** → template injection, dev mode in production
- **React/Vue** → sensitive data in client-side state (`__NEXT_DATA__`, `__vue__`)

### CDN/WAF
- **Cloudflare** → origin IP leakage, bypass techniques
- **AWS CloudFront** → S3 bucket exposure
- **Akamai** → edge vs origin

## Security Assessment

The `tech_stack_analyze` tool automatically provides:
- Technology categories and versions
- Security concerns per technology
- Recommended follow-up tools
- CVE research hints

## Additional flags

WhatWeb aggression levels:
- `1` (default) — passive, safe, no side effects
- `2` — uses plugins that need more HTTP requests
- `3` — aggressive, may trigger WAF/IDS
- `4` — very aggressive, may cause side effects

## After detection

1. Record findings with `platform_record_finding` (finding_type: technology)
2. Check `tech_dispatch.yaml` for automated follow-up suggestions
3. Research specific versions for known CVEs
4. Use technology knowledge to guide targeted scanning (e.g., WordPress → wpscan, nuclei)
