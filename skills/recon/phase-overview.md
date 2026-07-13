# Recon Phase

Goal: map the external attack surface before intrusive network testing.

**Workflow (suggested, not mandatory):**
1. Subdomain enumeration on the root domain
2. Live host probing on discovered hosts
3. Historical URL / archive mining for hidden endpoints
4. Light crawling on high-value URLs
5. DNS intelligence when nameservers or zone data are unclear

**Tool selection:** Pick the tool that fits the current finding. You may use any CLI flags via `additional_args` — examples in the catalog are hints only.

**Output:** Emit structured findings (subdomains, URLs, technologies). Reference prior finding IDs in `based_on_findings` when pivoting.
