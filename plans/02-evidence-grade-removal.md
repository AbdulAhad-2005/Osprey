# Plan 02 — Evidence-Grade Removal + Parser Severity Honesty

**Baseline:** `d7a4594` · **Risk:** HIGH (schema + DB column + 47 files) · **Depends on:** nothing · **The two halves MUST land together** (removing the grade without fixing parser severity re-introduces the false-positive it was masking).

## Why

The 2-D system (`evidence_grade` × `claim_severity`, where grade clamps severity) produces dishonest labels and is being deferred to a future compliance mode. Concretely at `d7a4594`:
- Every `VULNERABILITY` finding defaults to `EvidenceGrade.OBSERVED` (`schemas/finding.py:144-148`) merely for being a live response, which *unlocks* CRITICAL.
- `parse_sqlmap` emits `severity=CRITICAL, confidence=CONFIRMED` for a bare "is vulnerable" verdict with **no `--dump`** (`parsers/vuln.py:388, 405`).
- `parse_nuclei` hardcodes `confidence=CONFIRMED` for every template match (`parsers/vuln.py:173`).
- `clamp_claim_severity` (`finding.py:105-121`) silently downgrades any severity above the grade's ceiling, erasing the original claim with no record.
- The human-readable Markdown report drops grade entirely, so none of this nuance reaches the reader anyway.

**Decision:** remove the grade dimension; keep `claim_severity` as the single honest severity; make parsers assign severity by what the tool actually *proved* (detection vs exploitation). Grade returns later as a compliance feature, designed properly, not as today's optimistic default.

## Blast radius (47 files matched `evidence_grade|EvidenceGrade|clamp_claim_severity|default_grade_for_type`)

Code (must rework): `schemas/finding.py`, `models/finding.py`, `backend/alembic/versions/0001_baseline.py` (+ new migration), all parsers (`parsers/vuln.py`, `web_recon.py`, `recon_network.py`, `network_enum.py`, `osint.py`, `freeform_probe.py`, `browser.py`, `creds.py`, `dynamic_fallback.py`, `_capping.py`, `registry.py`), `findings_store.py`, `ingest_promoter.py`, `finding_correlator.py`, `exploit_pipeline.py`, `exploit_chain_store.py`, `operator_recall.py`, `operator_memory.py`, `handoff_dossier.py`, `evidence.py`, `engagement_graph.py`, `schemas/engagement_graph.py`, `commander_context.py`, `summary_agent.py`, `report_generator.py`, `report_outline.py`, `visualization.py`, `tool_execution.py`, `api/v1/endpoints/hybrid.py`, `api/v1/endpoints/findings.py`, `config/ingest_rules.yaml`, `config/correlation_rules.yaml`, `mcp-servers/osint/tools/email_permute.py`, `platform-mcp/server.py`.
Docs/skills (update text): `docs/*.md`, `skills/vuln/verification-and-severity.md`, etc.

## Steps

### Step 1 — Decide the severity-only contract first (write it down, then code to it)
Before touching code, write the honest severity rules parsers will follow, in `skills/vuln/verification-and-severity.md` (rewrite it — it currently teaches the grade system):
- **Detection without proof of impact** (sqlmap says "vulnerable" but no data dumped; nuclei template matched; version-based CVE guess) → `HIGH` max, `confidence=LIKELY`, and the title/description must say "detected", not "confirmed"/"exploited".
- **Proven exploitation** (data actually extracted, shell obtained, credential validated, file read returned) → may reach `CRITICAL`, `confidence=CONFIRMED`.
- **Passive / inferred** (DNS/CT/name signals, sister domains) → `LOW`/`INFO`.
This doc is the spec Steps 4-5 implement.

### Step 2 — Schema (`schemas/finding.py`)
- Delete `class EvidenceGrade` (72-77), `_MAX_SEVERITY_FOR_GRADE` (98-102), `clamp_claim_severity` (105-121), `default_grade_for_type` (124-185), the `evidence_grade` field (198), and the `_derive_grade_if_missing` validator (222-243).
- Keep `ClaimSeverity`, `_SEVERITY_RANK`, `FindingConfidence`, `claim_severity` field.
- If `_SEVERITY_RANK` is now only used by the deleted clamp, check its other consumers (grep) — keep it only if something else (sorting) uses it.

### Step 3 — DB model + migration
- `models/finding.py`: remove the `evidence_grade` column.
- Add a new Alembic migration under `backend/alembic/versions/` that drops the `evidence_grade` column (and, if present, any index on it). Do **not** edit `0001_baseline.py` in place — add a forward migration. Provide a downgrade that re-adds a nullable column so the migration is reversible.
- Confirm no model elsewhere has a FK/constraint referencing it.

### Step 4 — Parsers: remove `grade=` and assign honest severity (the merged severity-honesty half)
This is where plan-01's sibling fix lives — done here so `parsers/vuln.py` lines are rewritten once.
- Delete every `grade=` / `evidence_grade=` argument and every `EvidenceGrade` import across all parser files.
- `parsers/vuln.py` `_vuln_finding` (signature ~53-63): drop the `grade` parameter entirely.
- `parse_sqlmap` (~342-411): the no-dump "is vulnerable" branch at `388` and `405` → change `severity=ClaimSeverity.CRITICAL, confidence=CONFIRMED` to `severity=ClaimSeverity.HIGH, confidence=LIKELY`, and change description wording from "confirmed a SQL injection" to "detected a SQL injection (not yet exploited)". A separate branch that fires only when a dump/rows/`--os-shell` output is actually present may assign `CRITICAL, CONFIRMED` — add that branch only if the parser can observe real extraction in stdout; if it can't, everything sqlmap produces is detection → HIGH.
- `parse_nuclei` (~117-178): remove the hardcoded `confidence=CONFIRMED` at `173`; take severity from the template's own rating (already mapped via `_sev`) and set `confidence=LIKELY` for a template match (a match is detection, not exploitation). Only info/fingerprint templates → `INFO`.
- Audit the other `EvidenceGrade.OBSERVED`/`INFERRED` sites (`vuln.py:105,315,317,361,465`, and the same pattern in other parser files) — each becomes a direct, honest `claim_severity`/`confidence` with no grade.

### Step 5 — Consumers that *read* grade (Reconnect)
Each of these must be reworked to a grade-free equivalent, not stubbed:
- **`report_outline.py`** buckets findings under a section literally titled "Observed (proof)" keyed on `evidence_grade==OBSERVED` (~76-77,101). Re-bucket by `claim_severity` (Critical/High/Medium/Low/Info) or by `confidence`. Remove the "proof" wording unless backed by real exploitation.
- **`report_generator.py`** includes `evidence_grade` in the JSON payload (~94-114) — remove the field; ensure `claim_severity` + `confidence` are present.
- **`markdown_report.py`** already omits grade; ensure it now shows `confidence` alongside `[severity]` so "detected" vs "confirmed" is visible to the reader.
- **`ingest_promoter.py`**, **`finding_correlator.py`**, **`config/ingest_rules.yaml`**, **`config/correlation_rules.yaml`**: any rule keyed on grade (e.g. "cap correlated hypotheses at inferred") must be re-expressed in terms of `confidence` (HYPOTHESIS/LIKELY/CONFIRMED) — that enum already carries the "how sure" signal grade was duplicating.
- **`operator_memory.py`** / **`operator_recall.py`**: the "promote hypothesis_ link to observed for CRITICAL claims" logic must switch to `confidence`.
- **`exploit_pipeline.py`** / **`exploit_chain_store.py`**: grade references here interact with plan 04 — see plan 04 for the "proven" redefinition; within *this* plan just remove the grade references and use `confidence`/`finding_type`.
- **`findings_store.py`**: any sort/filter on grade → sort/filter on `claim_severity`.
- **`commander_context.py`**, **`handoff_dossier.py`**, **`visualization.py`**, **`api/v1/endpoints/{hybrid,findings}.py`**, **`platform-mcp/server.py`**: remove grade from any output/serialization; verify nothing returns a now-missing key to a client.

### Step 6 — Purge remaining traces
`grep -rn "evidence_grade\|EvidenceGrade\|clamp_claim_severity\|default_grade_for_type" backend platform-mcp mcp-servers config docs skills cli` must return nothing but this plan. Update every doc/skill line that describes the grade system (rewrite, don't just delete the sentence, where it explained methodology).

## Done criteria
- The grep above is empty.
- `cd backend && python -m pytest tests/ -q` passes (update tests that asserted on grade — they must now assert on `claim_severity`/`confidence`).
- Migration runs clean up and down against a scratch DB.
- A sqlmap "vulnerable, no dump" fixture produces a `HIGH`/`LIKELY` finding whose text says "detected", not "confirmed"/"exploited".
- A nuclei template-match fixture produces `confidence=LIKELY`, severity from the template, never a hardcoded CONFIRMED.
- The Markdown report shows severity **and** confidence per finding.

## STOP-and-report conditions
- If any DB row's behaviour depends on reading back a persisted `evidence_grade` value at runtime (not just writing it), STOP — that means a consumer wasn't in the list above; report it before dropping the column.
- If `confidence` turns out to be used somewhere as a *duplicate* of grade in a way that conflicts, STOP and reconcile the two enums' meaning before proceeding (don't leave two overlapping "how sure" signals).
