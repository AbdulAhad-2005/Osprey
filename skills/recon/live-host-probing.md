---
name: live-host-probing
description: "Probe hostnames for live HTTP(S) with httpx_probe (title, tech, status, redirects); the gate between discovered hosts and deeper testing."
phase: recon
tags: [recon, httpx, live-hosts]
---

# Live Host Probing

**When:** You have a list of hostnames or need to verify HTTP(S) reachability.

**Default:** `httpx_probe` with targets in `target` or `url` param (newline-separated or single).

**Useful `additional_args` examples (not exhaustive):**
- `-title -tech-detect -status-code -follow-redirects`
- `-threads 50` for large lists

**Input:** Pipe subdomains from prior findings or pass a file path if the tool supports it via flags.

**Output:** Live URLs, status codes, technologies — feed into crawling or historical URL tasks.

## WAF pivot families (examples — not exhaustive)
- Path: `/index.php/`, `/api/`, trailing dot, case variants
- Headers: `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`
- Method: GET vs POST on same path
- Historical: waybackurls may hit unprotected old endpoints

Use httpx `additional_args` for any of these. Combine with graph pivot (siblings on same IP).
