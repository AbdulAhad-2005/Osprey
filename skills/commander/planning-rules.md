---
name: planning-rules
description: "Judgment helpers for planning: prefer live evidence over hostname keywords, parsed findings over chat memory, and pick the next step that closes a concrete gap."
phase: commander
tags: [methodology, planning]
---

# Judgment helpers (not a checklist)

These are instincts of a strong operator — apply when they fit.

## Evidence over narrative

- Live response (status, title, banner) > hostname keywords  
- `evidence_grade=observed` + raw body/banner > inferred DNS/CT/port lists  
- Parsed finding / artifact file > chat memory of a truncated dump  
- One confirmed crown jewel > fifty unverified “HIGH” / CVE-title rows  

## Severity

- CRITICAL/HIGH only with observed evidence (banner, HTTP body, unauth API, etc.)  
- Nuclei/CVE **title alone is not enough** — store the response body snippet via
  `platform_record_finding(evidence=…)` or the tool must leave raw_data  
- Port-flood hosts → assume decoy until 2–3 services verified  
- Platform clamps claim_severity to the evidence grade — do not fight it in prose  
- Finalize blocks COMPLETE on weak CRITICAL/CVE claims  

## Tool choice

- Typed recon/network MCP tools first (clear schemas).  
- `platform_exec` second (aliases remap).  
- `platform_shell` / `platform_script` for invention — not to “fix” aliases.  
- `platform_playbook` when sequencing is unclear — advisory only.  

## When to deepen vs summarize

Deepen when the user wants coverage and hostnames dwarf verified ports/apps,
or when `platform_finalize_check` is BLOCKED.  
Summarize when the goal is a snapshot, the user says stop, or finalize is ALLOWED
(and remaining work is low-value noise).

## Visibility

Private CoT is invisible. Use `platform_think` and chat narration every pivot.
After tools, quote counts + crown jewels — do not leave results only inside MCP JSON.

## When tools fail

Say so. Read the gap note + error. Change the experiment (script, chunk size,
flags, different binary). Identical retries may cache-hit — change params if needed.

## Scope & ethics

Honor explicit limits. Ask when scope is ambiguous. Authorized testing only.
