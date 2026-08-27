---
name: injection-testing
description: "Targeted SQLi/XSS testing on recon's discovered parameters (injection_point candidates) with sqlmap and dalfox; test those inputs and prove impact."
phase: vuln
tags: [vuln, sqli, xss]
---

# Injection testing — SQLi & XSS on recon's parameters

Injection testing is **targeted**, not sprayed. Recon already found the inputs: every
`injection_point_candidate` (from `arjun_scan` / passive param mining), every query parameter on
an interesting endpoint, every form field. Test *those*, with the right tool, and prove it.

## SQL injection — `sqlmap_scan`

- Point it at a specific parameterised URL (`url=http://host/item?id=1`) or a POST body
  (`data="user=x&pass=y"`). It runs `--batch` (non-interactive).
- Confirmed injections are parsed into CRITICAL `vulnerability` findings with the parameter,
  technique, and back-end DBMS. An explicit "not injectable" result is recorded too — a useful
  negative, not noise.
- Scope discipline: proving injectability (detection) is analysis. `--dump`, `--os-shell`,
  reading files, or extracting data is **exploitation** — stop at proof unless the engagement
  authorises more. Keep the default risk/level low first; raise `--level`/`--risk` via
  additional_args only when a candidate looks promising and scope allows.

## Cross-site scripting — `dalfox_xss_scan`

- `url=` a parameterised endpoint. dalfox mines DOM/params and **verifies** reflections by
  executing payloads.
- Results distinguish **verified** (type V → HIGH, OBSERVED — a real, firing XSS) from
  **reflected/grep leads** (type R/G → LOW, INFERRED — needs manual confirmation). Trust the
  verified ones; treat leads as follow-ups.
- `blind=true` (with a `--blind-url` callback via additional_args) catches stored/blind XSS that
  reflect nowhere in the response.

## Workflow

1. Pull the parameter leads from recon (`platform_context` / findings tagged
   `injection_point_candidate`, `interesting_path`).
2. Pick the tool by class: SQLi → sqlmap, XSS → dalfox. Other classes (SSRF, SSTI, XXE,
   deserialization, NoSQL, open-redirect, mass-assignment) → `nuclei_scan` tags for the easy
   cases plus a crafted `platform_script` for the high-impact ones — methodology in
   `advanced-injection-classes`.
3. Test one candidate at a time on high-value endpoints; batch the rest via `platform_job_start`.
4. Record the confirmed injection with its parameter and a reproducing request as evidence.

## Do not

- Fuzz random parameters you didn't discover — test recon's actual inputs.
- Escalate a *reflected* (unverified) XSS lead to HIGH — it's INFERRED until verified firing.
- Cross from proof into data exfiltration / shell without explicit authorisation.
- Hammer a WAF-fronted endpoint — you'll get banned and blame the app; note the WAF and adapt.
