---
name: elite-reliability-flexibility
overview: "Most reported issues are valid, but several should be merged or reframed: artifact/output, jobs, Nmap normalization, deltas, attempt provenance, evidence traversal, correlation provenance, and SPA response scoping need work; job listing and finalize override already exist, while findings-summary emptiness is not reproduced. The implementation keeps the motto: the platform supplies durable evidence, safe execution primitives, and transparent policy; the LLM chooses experiments and meaning."
todos:
  - id: tracker-contracts
    content: Normalize verified reports into one root-cause tracker and define generic execution/evidence/policy contracts
    status: pending
  - id: execution-correctness
    content: Fix artifact pagination/framing and canonical Nmap port-selector normalization
    status: pending
  - id: durable-jobs
    content: Implement durable executions/jobs, cancellation, cleanup, partial output and restart reconciliation
    status: pending
  - id: safe-shell
    content: Add structured pipeline/stderr/artifact controls while retaining governance
    status: pending
  - id: memory-truth
    content: Persist full attempt provenance and replace global deltas with cursor-based changes
    status: pending
  - id: evidence-intelligence
    content: Implement bidirectional evidence DAG and provenance-rich correlation candidates
    status: pending
  - id: http-classification
    content: Make SPA/API classification response-scoped and corroborated
    status: pending
  - id: policy-hardening
    content: Add layered effective policy and audited finalize decisions without exposing safety controls
    status: pending
  - id: contract-dry-run
    content: Add version handshake, full contract tests and authorized end-to-end reliability dry run
    status: pending
isProject: false
---

# Elite Reliability and Flexibility Plan

## Verified issue disposition

- **Confirmed:** artifact framing/large-file reading, job cancellation and stale-job handling, partial output absence, context delta’s triple-snapshot bug, lossy attempt identity, incomplete descendant evidence traversal, provenance-poor/non-idempotent correlations, and SPA false positives.
- **Partly valid:** shell redirection is restrictive by design and needs structured stderr/artifact controls—not raw metacharacter access; `nmap_custom_scan` preserves `-p` in flags but silently ignores the generic `ports` field; config is readable but runtime tuning is limited.
- **Incorrect as stated:** job listing already exists through empty `platform_job_poll()` and `GET /jobs`, but it is poorly discoverable and non-durable; finalize override already exists, but is unaudited and inconsistently propagated; findings summary emptiness is not supported by the current successful path, so add diagnostics/tests before changing behavior.
- Merge “artifact empty” and “large artifact silent failure” into one root issue. Merge duplicate “attempt parameters invisible” reports.

## Engineering motto and non-negotiable rules

- **Do not hardcode engagement sequences. Help the LLM become elite.** Expose facts, provenance, capabilities, progress, policy and safe primitives; the LLM chooses the next question and experiment.
- Never auto-start tools, auto-accept correlations, or turn confidence scores into fixed tool chains.
- Keep scope, command allowlisting, scan budget, evidence-grade clamps and non-overridable claim-integrity checks as hard referee boundaries.
- Make attempts and evidence append-only and auditable. Derived projections such as coverage and crown-jewel scores may be rebuilt.
- Every automatic inference must carry source finding IDs, excerpts, rationale, rule version and a stable fingerprint.
- Every phase begins with failing reproducer/contract tests and ends with Docker tests plus one authorized smoke scenario.

## Phase 0 — Normalize the tracker and contracts

- Create `docs/PLATFORM_RELIABILITY_TRACKER.md` with one canonical issue per root cause, verified status, reproducer, expected behavior, acceptance criteria and owning phase.
- Define generic contracts before implementation: `ExecutionAttempt`, `ExecutionHandle`, `ArtifactSlice`, `ProgressSnapshot`, `EvidenceCandidate`, `EvidenceTraversal`, `ContextCursor`, and `EffectivePolicy`.
- Add finding IDs, execution IDs, job IDs, policy hash and artifact references consistently to MCP output.
- Primary files: [backend/src/pentest_platform/schemas/tools.py](backend/src/pentest_platform/schemas/tools.py), [backend/src/pentest_platform/schemas/jobs.py](backend/src/pentest_platform/schemas/jobs.py), [platform-mcp/server.py](platform-mcp/server.py).

## Phase 1 — Fix execution correctness first

### Artifact transport
- Replace mixed buffered text/raw-byte framing in [backend/src/pentest_platform/services/artifacts.py](backend/src/pentest_platform/services/artifacts.py) with true seek-and-read slicing and separate metadata.
- Read only `offset..offset+limit`; support UTF-8 replacement and optional base64 for binary data; report missing files and EOF explicitly.
- Persist uncapped stdout/stderr to canonical engagement artifacts; truncate only MCP cards. Validate canonical paths and reject traversal/symlink escape.

### Nmap normalization
- Refactor [backend/src/pentest_platform/services/command_builder.py](backend/src/pentest_platform/services/command_builder.py) to build tokenized argv.
- Normalize `ports`, `flags`, and `additional_args` into one final selector. Convert `ports="22,443"` to `-p 22,443`; if selectors conflict, return an ambiguity error. Apply `-F` only when no selector was supplied.
- Generate per-tool typed arguments in [platform-mcp/typed_recon_network.py](platform-mcp/typed_recon_network.py) instead of presenting irrelevant generic fields.

### Acceptance
- Artifact tests cover small/large/binary files, offsets, EOF, UTF-8 boundaries, missing files and traversal.
- Nmap tests assert exact argv for typed ports, free flags, additional args, conflicts, default fast scan and full-range governance.

## Phase 2 — Durable executions, jobs and cancellation

- Introduce append-only Postgres `executions` and durable `jobs` records via Alembic. Store normalized request, effective argv/command, cache key/hit, timeout, status, timestamps, job ID, policy hash, artifacts and result summary.
- Keep `tool_coverage` as a derived projection; stop using its unique `(engagement, tool, asset)` row as history.
- Replace the process-local-only state in [backend/src/pentest_platform/services/job_store.py](backend/src/pentest_platform/services/job_store.py) with a state machine: `queued → running → cancel_requested → cancelled|completed|failed|interrupted`.
- Add leases/heartbeats and startup reconciliation. Expired running jobs become interrupted unless an executor can prove they are still alive.
- Introduce a generic executor interface: `start`, `poll`, `read_output(offset)`, `cancel`, `reconcile`. Use it for catalog tools, shell and scripts—no per-tool workflow logic.
- Execute in an identifiable process group or isolated ephemeral container. On timeout/cancel: TERM, grace period, KILL, await/reap, persist final state.
- Spool stdout/stderr continuously to durable artifacts and expose offsets while running.
- Add `DELETE /jobs/{id}` or `POST /jobs/{id}/cancel`, job output/progress endpoints, and MCP `platform_job_cancel` plus an explicit `platform_job_list`. Retain empty `platform_job_poll()` for polling semantics only.
- Primary files: [backend/src/pentest_platform/services/job_store.py](backend/src/pentest_platform/services/job_store.py), [backend/src/pentest_platform/services/mcp_client.py](backend/src/pentest_platform/services/mcp_client.py), [backend/src/pentest_platform/api/v1/endpoints/jobs.py](backend/src/pentest_platform/api/v1/endpoints/jobs.py), [backend/src/pentest_platform/schemas/jobs.py](backend/src/pentest_platform/schemas/jobs.py).

## Phase 3 — Safe shell flexibility

- Do **not** allow arbitrary `2>&1`, redirects or shell expansion as raw text.
- Replace the string-only shell path with a constrained command AST: allowlisted argv stages, explicit pipeline edges, `stderr_mode=separate|merge|discard`, and artifact-backed output destinations.
- Permit output files only under the engagement workdir after canonical-path validation. Continue rejecting `&&`, backgrounding, command/process substitution, arbitrary file descriptors and device paths.
- Execute validated argv pipelines without interpolating raw user input into `bash -c` where possible.
- Preserve the current simple string interface as a parser into the structured request, not as the source of truth.
- Primary files: [backend/src/pentest_platform/services/shell_exec.py](backend/src/pentest_platform/services/shell_exec.py), [backend/src/pentest_platform/api/v1/endpoints/mcp.py](backend/src/pentest_platform/api/v1/endpoints/mcp.py), [platform-mcp/server.py](platform-mcp/server.py).

## Phase 4 — Memory truth, attempts and deltas

### Attempt provenance
- Make `platform_attempts` read append-only executions. Show normalized params, additional args, effective command/argv, cache key/hit, force refresh, timeout, job/execution IDs, timestamps, artifact paths and outcome.
- Redact secrets before persistence/display and return a stable request fingerprint so the LLM can distinguish identical reruns from new experiments.
- Update [backend/src/pentest_platform/services/operator_recall.py](backend/src/pentest_platform/services/operator_recall.py) and [backend/src/pentest_platform/services/tool_coverage_store.py](backend/src/pentest_platform/services/tool_coverage_store.py).

### Context delta
- Fix [backend/src/pentest_platform/services/commander_context.py](backend/src/pentest_platform/services/commander_context.py) so adaptive context computes counts once, then attaches elite metadata once.
- Replace global consume-on-read snapshots in [backend/src/pentest_platform/services/context_delta.py](backend/src/pentest_platform/services/context_delta.py) with durable event cursors: `delta_since=<cursor>` returns absolute counts, changes since cursor and a new cursor. Scope by engagement and consumer/run.

### Findings summary
- Do not assume a bug. Add explicit `{count, summary, generated_at, truncated, engagement_id, run_scope}` and contract tests for zero/nonzero findings, run rotation and MCP formatting.
- Always print finding IDs in `platform_findings` for evidence-chain navigation.

## Phase 5 — Evidence DAG and actionable correlation candidates

### Evidence traversal
- Build exact-ID forward and reverse adjacency for `derived_from`; traverse ancestors and descendants to requested depth with cycle detection, distance/path metadata and truncation flags.
- Validate every parent exists in the same engagement when writing. Attach execution/artifact provenance automatically to parsed findings.
- Update [backend/src/pentest_platform/services/operator_recall.py](backend/src/pentest_platform/services/operator_recall.py) and [backend/src/pentest_platform/services/evidence_chain.py](backend/src/pentest_platform/services/evidence_chain.py).

### Correlations
- Change [backend/src/pentest_platform/services/finding_correlator.py](backend/src/pentest_platform/services/finding_correlator.py) from automatically writing generic links to emitting **correlation candidates**.
- Each candidate includes concrete source/target assets, contributing finding IDs, quoted excerpts, positive/negative features, confidence rationale, rule/profile version, required confirmation and stable fingerprint.
- Add accept/reject/rename/deepen operations so the LLM authors the final relation. Accepted candidates call `platform_graph_link` with `derived_from`; rejected candidates remain auditable and do not reappear unchanged.
- Make correlation runs incremental and idempotent rather than rescanning 2,000 findings after every ingest.
- Keep [config/correlation_rules.yaml](config/correlation_rules.yaml) declarative: thresholds and evidence requirements, never tool sequences.

## Phase 6 — Response-scoped HTTP/SPA classification

- Stop classifying the entire combined stdout/stderr blob as one response in [backend/src/pentest_platform/services/ingest_promoter.py](backend/src/pentest_platform/services/ingest_promoter.py).
- Introduce structured HTTP response envelopes: URL, requested path, status, content type, headers, body hash, parsed-body type and source finding ID.
- HTML is only a candidate signal. Confirm catch-all behavior by comparing an API-looking path with a random nonexistent path/root signature or another configured corroboration method.
- Demote only the affected response/claim; never demote independently valid JSON because HTML appeared elsewhere in output.
- Move marker sets, required corroboration count, ignored content types and demotion scope into typed evidence profiles. Add ordinary HTML, mixed JSON+HTML, Express SPA/API and true catch-all tests.
- Keep finalize protection conservative, but consume the response-scoped classification rather than broad regex over concatenated evidence.

## Phase 7 — Layered policy without surrendering safety

- Keep `platform_config` read-only for global files. Fix [backend/src/pentest_platform/services/knowledge_browser.py](backend/src/pentest_platform/services/knowledge_browser.py) to prefer YAML, matching runtime and `config/README.md`.
- Add typed layered policy resolution: platform defaults → named evidence profile → engagement overrides → per-call experimental overrides. Return effective values, source, version/hash and validation errors.
- Allow only non-safety engagement preferences through an operator-confirmed tool: soft parallel hint threshold, context limits, correlation profile and report outline size. Increasing actual concurrency, changing allowlists, scan budget or hard claim-integrity rules requires an admin/operator authorization boundary.
- Persist finalize override decisions with actor, explicit reason, timestamp, policy hash, overridden blocker classes and expiry. Config declares which blockers are overridable; report outline/context consume the persisted decision while still showing original blockers.
- Primary files: [backend/src/pentest_platform/services/parallelism_config.py](backend/src/pentest_platform/services/parallelism_config.py), [backend/src/pentest_platform/services/finalize_rules.py](backend/src/pentest_platform/services/finalize_rules.py), [backend/src/pentest_platform/services/finalize_readiness.py](backend/src/pentest_platform/services/finalize_readiness.py), [platform-mcp/server.py](platform-mcp/server.py).

## Phase 8 — Contract hardening and authorized dry run

- Add backend/MCP version and capability handshake so stale route tables fail with “restart backend/reload MCP,” not generic 404.
- Add MCP-to-API contract tests for every wrapper, migration/restart tests, cancellation/process-leak tests, artifact persistence tests and redaction tests.
- Mount the engagement artifact root as a durable Docker volume; reconnect executions to artifacts after backend/container restart.
- Run one authorized engagement exercising: artifact pagination, exact Nmap ports, merged stderr, job cancellation, partial output, restart reconciliation, attempt provenance, delta cursors, correlation accept/reject, multi-level evidence traversal, SPA mixed responses and finalize override auditing.
- Update the tracker with measured evidence and close only issues whose acceptance tests pass.

## Handoff rules for the implementing engineer

- Work one phase per branch/PR; keep migrations separate from behavioral changes when possible.
- Begin each issue with the real OpenCode reproducer, then add the smallest generic abstraction that fixes the class of failures.
- Do not add per-vendor packs, static next-tool rankings, mandatory stage enums or automatic execution.
- Do not weaken safety to improve convenience: express safe flexibility through typed requests and capability contracts.
- Preserve raw evidence and effective execution identity before adding more scoring or intelligence.
- Run Docker tests after every phase; local missing optional dependencies are not a reason to bypass the Docker source of truth.
