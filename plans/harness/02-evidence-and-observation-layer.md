# Plan 02 — Evidence & Observation layer (parsers stop deciding truth)

**Baseline:** `10d13ae` · **Risk:** High (touches every parser + the ingest path) ·
**Depends on:** 00, 01 (so the change is measurable) · **Size:** ~2–3 weeks.

## Why

This is the disease. Parsers + `ingest_rules.yaml` + `dynamic_fallback.py` read raw tool
output and **mint findings** — that is the "HTTP 501 became a finding" generator. Strix never
does this (findings only via explicit filing); Pentest-Swarm never does this (raw signals
earn confidence through a pipeline). We adopt the shared rule of both:

> Parsers may **extract structure**. They may **not** decide something is a vulnerability,
> and they may **not** create a `Finding`.

ChatGPT's §5 correction is the exact boundary: `port=443, service=nginx` is safe structural
extraction; `"SQL injection found!"` from regex is not. So we **demote**, we do not blindly
delete (opencode's "delete all 71" was retracted).

## What exists now (verified)
- `parsers/` — 13 modules, ~68 `parse_*` functions. Many emit `Finding(...)` with a
  severity/confidence directly.
- `ingest_promoter.apply_ingest_rules` + `config/ingest_rules.yaml` (29 rules) — regex →
  `Finding`.
- `dynamic_fallback.py` — asks the LLM to emit findings directly, skipping any evidence layer.
- Manufacture call-sites: `tool_execution.py`, `script_exec.py`, `shell_exec.py`,
  `package_install.py` (all call `summarize_execution` + `apply_ingest_rules`).
- `FindingType.OBSERVATION` already exists; raw stdout already persisted to disk (Plan 01).

## Target shape

```
tool runs → raw evidence (immutable, already ~exists)
                │
                ▼
   STRUCTURAL EXTRACTION (deterministic, safe)   ← rewritten parsers
                │   e.g. {port:443, service:nginx, version:1.24, status:501}
                ▼
        OBSERVATIONS (typed facts, provenance = evidence_id, confidence "observed")
                │
                ▼        (findings are NOT created here — see Plan 03)
        world model / coverage / questions
```

## Steps

### Step 1 — First-class Evidence record
- Promote the already-written raw stdout into a queryable `Evidence` row: `id, engagement_id,
  run_id, tool_name, target, command, stdout_path, stderr_path, exit_code, duration_ms,
  created_at, observed(bool)`. Reuse `stdout_index` + `artifacts` — this is a schema/model
  promotion, not new storage. Add an Alembic migration (batch-mode, SQLite+PG, tested like
  the prior migrations).
- `stdout` stays on disk (the `output_budget` truncation is for *driver visibility* only —
  Evidence always points at the full untruncated artifact).

### Step 2 — Observation model + store
- Add `Observation`: `id, engagement_id, run_id, evidence_id, type, details(json), confidence
  ("observed"), source_tool, target, extracted_by ("parser"|"llm"|"human"), signature`.
- `observation_store` with `record`, `list_by_target`, `list_by_type`, `list_for_engagement`.
- `Observation` is the *only* thing structural extraction is allowed to produce.
- **Dedup / volume control (required — this is high-volume data).** Every structural fact
  becomes an observation, so a single big engagement can produce tens of thousands of rows
  (every port, header, endpoint). Give each observation a deterministic `signature`
  (`type + target + normalized-details`); `record` is idempotent on signature — a re-scan
  merges into the existing row (bump `last_seen`, append `evidence_id`) instead of inserting a
  duplicate. Model this on the finding-dedup logic `findings_store` already has; do not
  reinvent it. This keeps the world model and context packet bounded as scans repeat.
- **Concurrency:** `observation_store` writes must be atomic under concurrent subagents — same
  requirement and rationale as Plan 05 Step 5 (parallel investigation writes here too).

### Step 3 — Rewrite parsers as structural extractors
- Each `parse_*` returns `list[Observation]` of **facts**, never `Finding`, never a severity,
  never a vulnerability verdict. Allowed observation types: `service`, `technology`,
  `endpoint`, `dns_record`, `http_response`, `header`, `banner`, `content_path`,
  `js_endpoint`, `email`/`username`/`person` (osint), etc.
- **Forbidden** in a parser now: `severity=`, `confidence=CONFIRMED`, `FindingType.VULNERABILITY`,
  any string like "vulnerable"/"injection found". A lint test enforces this (grep-gate in CI).
- Where a parser previously encoded genuinely useful *structure* extraction of a scanner's
  own verdict (e.g. nuclei says "template X matched"), that becomes an observation
  `type=scanner_signal, details={template, matcher, raw}` — a **fact that the scanner emitted
  a signal**, not a fact that a vuln exists. Plan 03 decides what that signal earns.

### Step 4 — Rip out the manufacture path
- **Delete** `dynamic_fallback.py` (LLM minting findings directly — no evidence layer).
- **Reduce** `ingest_rules.yaml` to *structural* extraction rules only; delete every rule
  whose output is a vulnerability verdict/severity. If nothing structural remains for a rule,
  delete it.
- Rewrite the four call-sites (`tool_execution.py`, `script_exec.py`, `shell_exec.py`,
  `package_install.py`): replace `summarize_execution + apply_ingest_rules` with
  `record_evidence → extract_observations`. No `Finding` is created on the tool-execution
  path anymore.

### Step 5 — LLM observation extraction (optional layer)
- Add `observation_engine.extract(evidence)` — when an LLM is configured, it reads raw
  evidence and returns additional observations the deterministic extractor can't (novel
  structure, unusual behavior). Confidence still `observed`; it extracts, it does not judge.
- Without an LLM: Step 3's deterministic extractors are the only source. Raw evidence is always
  present for a human.
- **Cost budget (required — this runs an LLM call per evidence item).** Do not extract on every
  tool output blindly. Gate LLM extraction: (a) skip evidence whose deterministic extraction
  already fully covered it (a clean nmap/httpx parse needs no LLM pass); (b) prioritize
  extraction on high-value or unstructured output (script/shell output, unusual responses) via
  the same `is_high_value` signal `output_budget` already uses; (c) batch multiple small
  evidence items into one call; (d) a per-engagement extraction-call budget in config, with the
  deterministic extractors as the always-on floor when the budget is hit. LLM extraction is an
  enhancement over the deterministic floor, never a per-tool tax.

## Reconnect
- `engagement_graph` currently ingests findings → now ingests **observations** (assets/edges
  are built from observations, not from verdicts). Covered fully in Plan 05.
- `findings_store` still exists but **nothing writes to it on the tool path** after this plan —
  it is written only by the earned-finding pipeline (Plan 03). **02 and 03 therefore ship as
  one atomic unit** (see README) — 02 is never released on its own, because between 02 and 03
  the product would produce zero findings and starve every finding reader
  (`report_outline`, `handoff_dossier`, `operator_recall`, `exploit_pipeline`). Treat "02"
  and "03" as two files describing one release.
- Coverage/prioritization (Plans 06) read observations.

## Done criteria
- `grep -rnE "severity=|confidence=FindingConfidence.CONFIRMED|VULNERABILITY" backend/src/osprey/services/parsers` returns nothing.
- No `Finding` is created anywhere on the tool-execution / script / shell path (grep the four call-sites).
- `dynamic_fallback.py` deleted; no importer remains.
- Replaying a synthetic fixture (Plan 01) whose only "signal" is an HTTP 501 produces an
  **Observation** (`http_response status=501`) and **zero Findings**.
- Benchmark delta recorded: `false_positive_rate` should drop sharply; `validated_finding_count`
  will temporarily drop too (findings now come from Plan 03) — that is expected and fine.
