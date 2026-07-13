# Finding Confidence

When recording or reasoning about findings:

- **confirmed** — Direct tool output (open port, HTTP 200, DNS record)
- **likely** — Inferred from multiple signals (tech stack guess, unverified subdomain)
- **hypothesis** — Pivot idea for next tool call (sister domain, possible admin panel)

Always cite `source_tool` and `evidence` from stdout when promoting a finding.
