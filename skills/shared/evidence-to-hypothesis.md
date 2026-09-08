---
name: evidence-to-hypothesis
description: "Universal evidence-to-hypothesis loop for unfamiliar products: expand, observe, hypothesize, verify — no per-vendor skill packs required."
phases: [shared]
tags: [methodology, reasoning]
---

# Evidence → hypothesis (universal thinking)

You will meet products you have never seen in this repo. That is normal.
There are **no per-vendor skill packs**. Do not wait for `oracle-*.md` or similar.

## Loop (always)

0. **EXPAND** — Sisters, subs, live, IPs, ports, web depth using the full resource set
   (see `shared/attack-surface-instincts`). Do not skip to product theater on a thin surface.
1. **SIGNAL** — Quote the fingerprint (header, banner, path, auth realm, tech string).
2. **NAME** — Using *your* knowledge, hypothesize product/family/role. Say uncertainty.
3. **CONFIRM** — Second observed probe on the same asset (status, title, headers, banner).
4. **GRADE** — `observed` / `inferred` / `unverified` before any severity word.
5. **DEEPEN** — After confirm, on high-value *roles*; invent with `platform_script` when needed.
6. **REPORT** — `platform_finalize_check`; never COMPLETE from chat memory.

Mirror expansion plans and steps 1–3 with `platform_think`. Context may include
`thinking_hypotheses` cards (including surface_widen_*) — follow their `think[]` list.

## Failures to avoid

- Treating DNS names (gitlab, jenkins, supplier, ebs) as proof of exposure
- CRITICAL from a single vendor header or console path
- HTML 200 on `/api` as “open API”
- Searching for a skill file instead of reasoning from the signal

## Platform helpers

- `platform_context` / thinking hypotheses — cards from evidence
- `platform_skills` — methodology (commander/recon/network), not vendor encyclopedias
- `platform_config(name='thinking_model')` — extendable signal classes (data, not code forks)
