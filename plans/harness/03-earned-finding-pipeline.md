# Plan 03 — Earned-finding pipeline (findings become outputs, not byproducts)

**Baseline:** `10d13ae` · **Risk:** High · **Depends on:** 02 · **Size:** ~2–3 weeks.
Ship 02+03 together behind the Plan 01 benchmark.

## The one law (universal — no per-type branching, ever)

> **A finding's confidence is a pure function of the evidence attached to it. A finding is
> only ever displayed at the confidence its evidence earns. You raise confidence by attaching
> more evidence — never by asserting it.**

`confidence = f(evidence)`. That sentence contains no finding *type*, no protocol, no vuln
class — and it must stay that way. This is what makes the system edge-case-proof: a vuln class
that does not exist yet is handled *identically* to one that does, because nothing branches on
the class. A `switch(type)` can only ever handle the cases someone enumerated (that is exactly
how "501 became a finding" happened); an invariant defined for all inputs has no unenumerated
case to get wrong.

**Hard prohibition (we have been burned by this before):** there is **no** `if type == …`,
`switch(finding_type)`, or per-type rule table anywhere in the finding/validation path. A lint
gate enforces it (Step 7). If you feel the urge to special-case a type, you are re-growing
`tech_dispatch.yaml` — stop.

## Design — evidence in, confidence out

After Plan 02 nothing manufactures findings. A `Finding` comes into existence exactly two ways,
and **both obey the one law above**:

1. **Explicit filing (Strix model):** the LLM/agent/human calls `file_finding` *after* it has
   gathered evidence. The caller cannot set confidence — it attaches evidence; `f(evidence)`
   computes confidence. Primary path when an LLM/human is driving.
2. **Deterministic promotion (Pentest-Swarm model):** the promoter attaches whatever evidence
   the safe capabilities produced and lets `f(evidence)` compute confidence. Primary path with
   no LLM.

There is **no "strategy selector."** What used to look like "5 strategies chosen by type" are
just **evidence-producing capabilities** the *reasoner* (LLM, planner, or human) may invoke —
exactly like tools. The system never picks one by type; the reasoner picks what evidence to go
get, and the system only ever computes `f(evidence)`:

| Capability (a way to *produce* evidence) | Evidence it attaches |
|---|---|
| run another tool | +1 corroborating `source_tool` |
| re-request / header / banner re-grab | a fresh confirming observation |
| controlled PoC (RoE + blast-radius gated) | a reproduction result (`_is_proven`) |
| read the config / permission directly | a verification observation |
| human attests | a human-attestation evidence record |

`f(evidence)` (uniform, tunable by the benchmark, applied to *every* finding regardless of type):
- no evidence beyond the raw signal → `hypothesis`
- corroboration (≥2 independent sources) **or** a passing safe check → `likely`
- a reproduction / direct verification / human attestation → `confirmed`

Cross-validation is therefore just *one input* to `f` (evidence, not confirmation — two scanners
can share a signature), and PoC is *one kind* of evidence, never a universal gate (weak TLS /
missing headers need no exploit — a config-verification observation clears the bar for them).

## What exists now (verified)
- `findings_store` has `add`, `add_many`, `add_many_result`, `list`, and grouping/upgrade
  logic that already tracks strongest confidence + highest severity.
- `FindingConfidence` = confirmed/likely/hypothesis (from prior work). Default now HYPOTHESIS (Plan 00).
- RoE gating + blast-radius already enforced in `tool_execution.py` (keep — the PoC strategy
  rides on it).
- Exploit candidate store + `_is_proven` predicate already exist (from prior exploit-truthfulness
  work) — reuse, don't duplicate.
- **Verified problem this plan MUST fix:** `exploit_pipeline.scan_for_candidates`
  (`exploit_pipeline.py:99-179`) currently promotes exploit candidates by reading **findings**
  (`get_findings_store().list(finding_type=VULNERABILITY/CREDENTIAL/SECRET)` + the
  `injection_point_candidate` tag). Plan 02 stops creating those findings on the tool path, so
  this input **dries up**. Worse, it creates a chicken-and-egg: a candidate's PoC is what
  *earns* a finding, but candidate promotion currently *requires* a finding to already exist.
  Step 6 re-sources it.

## Steps

### Step 1 — `Finding` = a claim + its evidence (confidence is never stored as an input)
- Add: `observation_ids: list[str]`, `source_tools: list[str]`, `evidence_records: list`
  (each a typed evidence item — corroboration / reproduction / verification / attestation),
  `evidence_summary: str`. (Keep existing `evidence`/`metadata`.) Alembic migration.
- **`confidence` is computed, not assigned.** It is a derived/read-only property equal to
  `f(evidence_records)`; there is no code path that *sets* a finding's confidence directly.
  A `Finding` with no `observation_ids` is illegal — assert at construction.

### Step 2 — `f(evidence)` — the single confidence function (one place, no type branching)
- One pure function `confidence_for(evidence_records) -> FindingConfidence`, the *only* thing
  in the codebase that decides confidence. Uniform over all findings:
  - only the raw signal → `hypothesis`
  - ≥2 independent `source_tools` corroborating, or one passing safe check → `likely`
  - a reproduction (`_is_proven`), a direct verification, or a human attestation → `confirmed`
- It reads *evidence records*, never `finding.type`. No `if type ==`. This is the universal law
  in code. Every other step just *attaches evidence*; this function alone maps evidence→confidence.

### Step 3 — `file_finding` capability (explicit path)
- MCP tool `platform_file_finding(title, type, severity, observation_ids, evidence_records, ...)`
  — the LLM/human calls it *after* gathering evidence. Only LLM→finding path (replaces the
  deleted `dynamic_fallback`). Requires ≥1 `observation_id`.
- The caller **cannot** pass a confidence — it attaches evidence and `confidence_for` computes
  the rest. A caller claiming "confirmed" with no confirming evidence record simply yields
  `likely`/`hypothesis`. Say-so is not evidence.

### Step 4 — Evidence-producing capabilities (a menu, not a selector)
- These are capabilities the *reasoner* (LLM / deterministic planner / human) may invoke to
  attach evidence — like tools. The **system never chooses one by finding type.** Each returns
  an evidence record that feeds `confidence_for`:
  - corroboration → run another independent tool; attaches a `source_tool`.
  - safe active check → a scoped re-request via the execution kernel; attaches an observation.
  - controlled PoC → reuse exploit-candidate/`_is_proven`, RoE + blast-radius gated; attaches a
    reproduction record.
  - config/permission verification → a targeted read; attaches a verification observation.
  - human attestation → attaches an attestation record.
- None of these "confirm" anything by themselves — they add evidence; `confidence_for` decides.
  Ambiguous/high-impact items simply lack a confirming record and stay `likely` + `needs_review`
  until a human attaches one. That is the universal handling of "human review," not a branch.

### Step 5 — Promotion path (deterministic, no-LLM)
- `promote_observations(engagement)` — the no-LLM route: clusters corroborating observations,
  invokes only the **safe** evidence-producing capabilities (corroboration, safe re-request,
  config verification), attaches what they produce, and lets `confidence_for` compute confidence.
  Destructive PoC is **never** auto-run without an LLM/operator + RoE.
- Without an LLM: a finding reaches `confirmed` only if a safe capability produced a confirming
  record; everything else stays a `likely`/`hypothesis` finding or a bare observation for a
  human. Honest, not manufactured. Same function, same law — just a smaller evidence menu.

### Step 6 — Re-source exploit-candidate promotion from observations (breaks the chicken-and-egg)
- Rewrite `exploit_pipeline.scan_for_candidates` to read **observations** (and, once Plan 05
  lands, attack-path hypotheses), **not findings**. A candidate is a *hypothesis to test* that
  exists **before** any finding — e.g. a `scanner_signal` observation (nuclei template matched),
  an `injection_point` observation (arjun/x8 mapped a parameter), a `service`+version observation
  matching a CVE, or a `credential`/`secret` observation. These are exactly the observation types
  Plan 02 produces.
- Flow becomes: observation → candidate (hypothesis) → controlled-PoC capability (Step 4) →
  **if it reproduces**, a reproduction evidence record is attached and `confidence_for` yields
  `confirmed`. This removes the chicken-and-egg: the finding is the *output* of the candidate's
  PoC, never a prerequisite for it.
- `_is_proven` stays the single definition of "proven" and is what the controlled-PoC capability
  calls. Keep it; only its *input* moves from findings to observations/candidates.
- Until Plan 05 lands, candidates may be sourced from observations alone; attach attack-path
  hypotheses as an input in Plan 05's reconnect.

### Step 7 — Lint gate: no per-type branching in the finding/validation path (the anti-regression)
- CI grep-gate (same style as Plan 02's "no `severity=` in parsers") over the finding-creation,
  `confidence_for`, and evidence-capability modules: **fail** on `finding_type ==`,
  `\.type ==`, `switch`/`match finding_type`, or any per-vuln-class rule table. Confidence and
  validation must branch on *evidence*, never on *type*. This is the guardrail that stops the
  pipeline from silently decaying back into `tech_dispatch.yaml`-style hardcoding during
  implementation — a failure mode we have hit before.
- The one legitimate use of `finding.type` is *display/reporting* (grouping a report by
  category) — never in deciding confidence or which validation runs. The gate allows it only in
  the report/render modules.

## Reconnect
- Report outline / handoff dossier / operator recall read `findings_store` — unchanged API,
  but findings now always carry `observation_ids` + validation provenance (richer reports).
  Because 02+03 ship as one atomic unit (README), these readers never see the empty-findings
  window; they simply switch from manufactured findings to earned ones in the same release.
- Graph (Plan 05) links findings to the observations/assets they were earned from.
- `exploit_candidate_store` feeds the controlled-PoC strategy — single source of "proven" — and
  is now driven by observations (Step 6), not findings.

## Done criteria
- The only code paths that create a `Finding` are `platform_file_finding` and
  `promote_observations`. `grep` proves no other writer.
- `confidence` is computed by exactly one function (`confidence_for`); **no** code path assigns a
  finding's confidence directly (grep + test). A `confirmed` finding always has a confirming
  evidence record.
- **Step 7 lint gate passes:** zero `finding_type ==` / `switch(type)` / per-type rule tables in
  the finding-creation, confidence, or validation modules. The same evidence law handles a
  finding type invented tomorrow with no code change.
- Replay of the synthetic "501 noise" fixture: **zero findings**. Replay of a fixture with a
  genuinely reproduced SQLi: exactly one `confirmed` finding carrying a reproduction record.
- Adding a brand-new finding type to a fixture (one the code has never seen) still flows
  hypothesis→likely→confirmed purely on its evidence — proving universality, not enumeration.
- Benchmark delta recorded: `confirmed_without_proof_count` → 0; `false_positive_rate` at or
  near 0 on synthetic fixtures; `validated_finding_count` recovers to real signal only.
