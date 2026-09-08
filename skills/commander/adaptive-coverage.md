---
name: adaptive-coverage
description: "After each meaningful result, ask what a skilled operator would ask next; turn soft coverage gaps into judgment about what to probe rather than following a fixed phase script."
phases: [commander]
tags: [methodology, coverage]
---

# Adaptive coverage — questions, not a script

You are not following phases. After each meaningful result, ask what a skilled
operator would ask. The platform surfaces soft gaps; you decide.

## After discovery

- What is live from the outside vs DNS-only?
- Is the perimeter web-shaped (mostly 80/443) or network-rich?
- If web-shaped: inventory is not depth — historical URLs, crawl, auth/API paths.
- Which 3–5 live hosts would repay time (name + role), not which 300 hostnames exist?

## After live probes

- Titles/status alone ≠ verified impact.
- Interesting hostname tokens (vpn, admin, mdm, api, gitlab, …) that are live but
  only title-probed → deepen those hosts before growing the list.
- Alt ports on the same host (8443, 8080, …) when 443 is boring.

## After network attempts

- Timeouts / missing tools → shrink scope; do not abandon the engagement.
- Port-flood hosts → verify 2–3 services before severity language.
- If non-web ports never appear, stop burning scans — switch to app depth.

## Sisters & noise

- Page-scrape “sisters” that are shorteners/CDNs/social → noise, not affiliates.
- Demand DNS/org proof before treating a sister as in-scope surface.

## Before “final”

- Call `platform_finalize_check`.
- If gaps say web_surface_no_app_depth or inventory_without_verification — deepen or
  ask the operator for an explicit partial-report override.
- Weak CRITICAL/CVE claims block COMPLETE — attach raw proof via `platform_record_finding`.
- Report what you observed, what you inferred, and what you never verified.
- If sequencing is foggy, `platform_playbook` for an advisory plan — then adapt.
