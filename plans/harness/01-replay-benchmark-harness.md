# Plan 01 — Replay & benchmark harness (build the ruler first)

**Baseline:** `10d13ae` · **Risk:** Low (new, additive) · **Depends on:** 00 · **Size:** ~1 week.

## Why this is first

Every architecture claim in the whole discussion — "no false positives," "deeper than
Strix," "better memory" — is **unfalsifiable without measurement**. ChatGPT correctly
called out the unfounded "we'll be best in 14 weeks." Neither Strix nor Pentest-Swarm can
prove superiority either. If we change the finding pipeline (Plans 02–04) without a ruler,
we are guessing. So the ruler comes before the surgery.

The good news: we already persist the raw material. `tool_execution.py:524-544` writes full
raw stdout to disk via `write_text_artifact` and indexes it via `record_stdout_entry`. That
is ~80% of a replay corpus already.

## What exists now (verified)
- Raw stdout artifacts on disk + `stdout_index` rows (path, tool, target, bytes, success).
- Audit log records every execution (`get_audit_log().record`).
- No mechanism to (a) capture a full engagement as a fixture, (b) re-feed recorded tool
  outputs to a new pipeline version, or (c) score an engagement.

## Steps

### Step 1 — Engagement recorder
- Add a recorder that, for an engagement, captures an ordered list of
  `(tool_name, target, params, command, stdout, stderr, exit_code, timestamp)` — sourced
  from the artifacts + stdout_index that already exist, plus params from the audit log.
- **Also capture LLM calls** made during ingestion/validation (request + response for
  observation extraction, `file_finding`, validation verdicts). This is what lets replay feed
  back fixed LLM decisions (see Step 2 determinism scope) — without it the ruler can't isolate
  pipeline-logic changes from LLM noise. Before Plan 02/03 land there are no such calls, so this
  is a no-op initially; wire the hook now so recordings taken after 02/03 are replayable.
- Serialize to a single portable fixture file per engagement
  (`benchmarks/recordings/<name>.jsonl`). This is the replay corpus.
- Recording must be **passive** — it reads what's already stored; it does not change the
  execution path.

### Step 2 — Replay driver
- A driver that takes a recording and re-feeds each recorded tool output **through the
  current ingestion/finding pipeline** without executing any real tool (tools are stubbed to
  return the recorded stdout/exit_code for the recorded params).
- Output: the set of Observations + Findings the pipeline produced for that recording.
- This lets us change Plans 02–04 and see exactly what the finding set becomes, on real data,
  in seconds.

#### Determinism scope (critical — the ruler must be stable)
After Plan 02/03 the ingestion pipeline contains **LLM calls** (observation extraction,
`file_finding`, some validation strategies). LLM output varies run-to-run, so a naive replay
is not a stable ruler for those parts. Handle it explicitly:
- **Deterministic layer** — structural extractors + cross-validation + the promotion pipeline's
  non-LLM logic run identically every replay. This is what the benchmark measures for
  regression, and where the false-positive / confirmed-without-proof gates live. It must be
  reproducible bit-for-bit.
- **LLM layer** — the recorder also captures each LLM request/response (extraction outputs,
  `file_finding` calls, validation verdicts) as part of the fixture. Replay **feeds back the
  recorded LLM responses** (LLM stubbed) so a pipeline-logic change is measured against fixed
  LLM decisions. To measure an *LLM/prompt* change instead, re-run with a live LLM in an
  explicit `--live-llm` mode and treat the result as a distribution (average over N runs), not
  a single deterministic number.
- The scorecard labels each metric as `deterministic` or `llm-dependent` so a "delta" is never
  silently comparing LLM noise. This keeps the measurement gate honest.

### Step 3 — Scoring
Implement the metrics ChatGPT's §14 named (the honest goal is "maximize validated discoveries
while minimizing missed surface, redundant work, false positives"):
- `false_positive_rate` — findings that a labeled fixture marks as not-real / thin-evidence
  (the "501 as evidence" class).
- `validated_finding_count` / `confirmed_without_proof_count`.
- `attack_surface_coverage` — distinct assets/services reached.
- `redundant_action_count` — same tool+params replayed with no new observation.
- `time_to_first_validated_finding` (from timestamps).
- `missed_known_vuln_count` — for synthetic fixtures with known-planted vulns.

### Step 4 — Labeled fixtures
- Record 3–5 real engagements (with permission) as fixtures.
- Build 2–3 **synthetic** fixtures with known planted vulnerabilities + known noise (an
  endpoint that returns 501, a banner that looks scary but isn't) so false-positive and
  missed-vuln rates are computable against ground truth.
- Store expected labels alongside each fixture (`<name>.labels.json`).

### Step 5 — CLI + CI entry point
- `osprey benchmark run [--fixture X]` → prints the scorecard.
- `osprey benchmark diff <baseline_run> <new_run>` → prints metric deltas.
- Wire into the existing regression-gate machinery so a PR can show its benchmark delta.

## Reconnect
- Nothing in production execution changes. This is a read-only corpus + an offline replay
  path. The replay driver reuses the *real* ingestion code (Plans 02–04 modify that code;
  replay automatically exercises the new version).

## Done criteria
- `osprey benchmark run` produces a scorecard for at least one recorded and one synthetic fixture.
- Changing a parser and re-running replay changes the scorecard **without** running any live tool.
- A synthetic fixture with a planted 501-noise endpoint yields a computable `false_positive_rate`.
- The scorecard for the current pipeline is captured as the **baseline** every later plan diffs against.
