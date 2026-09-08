---
name: nuclei-scanning
description: "Template-based vulnerability scanning with nuclei_scan against a live, tech-fingerprinted host; the default first vuln move."
phases: [vuln]
tags: [vuln, nuclei]
---

# Nuclei — template-based vulnerability scanning

`nuclei_scan` is the bridge from recon to vuln analysis: it runs a huge community template
set (CVEs, misconfigurations, exposures, default creds, takeovers) against a live target and
reports structured matches. It is the default first move once a host is confirmed live and its
tech is known.

## When and how

- **After tech is known.** Recon fingerprinted the stack (`whatweb`/`tech_stack_analyze`,
  `httpx`); now nuclei can match version- and product-specific templates. Scanning before you
  know the tech wastes time on irrelevant templates.
- **Signal first, breadth later.** Start `severity=critical,high` for the highest-value hits,
  then widen to `medium` and specific `tags` (`cve`, `rce`, `lfi`, `ssrf`, `exposure`,
  `takeover`). `template=` runs a specific template/dir when you're chasing one issue.
- **Batch live hosts** with `platform_job_start` — nuclei is slow; fan out over the host list
  while you do other work, don't block on one scan.
- Output is JSONL, parsed into `vulnerability` findings carrying template-id, CVE, CWE, and
  matched-at URL. You do not parse it yourself.

## Reading results

- A match is **OBSERVED** (nuclei got a live response) — that's why it can carry HIGH/CRITICAL.
  But nuclei has false positives: a template can match a version string without the host being
  exploitable. Treat `critical`/`high` CVE hits as **confirmed-present, exploitability-unverified**.
- `info`/`low` templates are mostly fingerprints and exposures (open dirs, panels, `.git`) —
  useful surface, rarely a finding on their own. They cannot exceed their low severity anyway.
- De-dupe by template + URL is done for you; focus on distinct issues, not repeated hits.

## Follow-ups by match

- **CVE with a public exploit** → note it; validation/exploitation is the next phase (needs approval).
- **Exposure** (`.git`, `.env`, backup, actuator, swagger) → fetch it (`platform_script` curl) to
  confirm it's real content, not a soft-404. Then it's an OBSERVED information-disclosure finding.
- **Takeover / default-cred template** → cross-check with the recon takeover findings.
- **WordPress/CMS hints** → switch to `wpscan_analyze` for deeper CMS enumeration.

## Do not

- Run the full template set at `info` on every subdomain first — you'll drown in fingerprints
  and may trip WAFs. Scope by severity and tags.
- Claim CRITICAL from a version-only template without a live corroboration — keep it at what
  the evidence supports (see `verification-and-severity`).
- Treat nuclei as exploitation. It confirms presence; it does not prove impact.
