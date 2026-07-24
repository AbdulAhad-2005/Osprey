# Elite Reliability Implementation Plan

## Purpose

This is the **new improvement plan** for the platform after Phases 1–7 were
implemented and stress-tested through OpenCode.

It is a delta plan. Do **not** reimplement the earlier cognition, open-gap,
ingest, correlation, job, finalize, and recall features from
`ELITE_OPERATOR_PHASED_PLAN.md`. Keep those capabilities and repair their
reliability, safety, provenance, and correctness.

The intended handoff is one independently reviewable phase at a time.

> **Motto:** We do not hardcode the engagement. We give the LLM trustworthy
> memory, safe execution primitives, transparent policy, and complete
> provenance so it can become an elite operator.

---

## 1. Desired architecture

The platform should remain:

```text
LAB
  tools + shell + scripts + jobs + fanout + artifacts

SHARED NOTEBOOK
  executions + findings + graph + evidence DAG + decisions

REFEREE
  scope + governance + scan budget + evidence law + report integrity

LLM
  chooses questions, experiments, relation meaning, confirmation, and stopping
```

The platform may:

- Enforce authorization and safety.
- Preserve exact execution and evidence history.
- Present gaps, signals, candidates, and confidence.
- Validate data and reject ambiguous requests.
- Explain which rule produced a decision.

The platform must not:

- Hardcode a mandatory engagement sequence.
- Automatically start tools because a signal matched.
- Automatically accept a correlation as fact.
- Turn a crown-jewel score into a fixed next-tool order.
- Add per-vendor agent stages for every technology.
- Hide request normalization or silently change operator intent.
- Discard evidence needed to reconstruct a claim.

---

## 2. Verified issue register

### 2.1 Critical safety and trust

| ID | Verified issue | Current consequence | Owning phase |
|---|---|---|---|
| GOV-01 | Registered-tool governance currently approves all tools | `GATED` and stored rules of engagement are descriptive rather than enforced | 1 |
| GOV-02 | Scripts bypass catalog/shell scan-budget checks | Custom code can perform work blocked through normal tool paths | 1 |
| GOV-03 | Finalize override is ephemeral and unaudited | COMPLETE can be forced without durable actor/reason/policy evidence | 8 |
| HTTP-01 | SPA/API classification uses combined output | Valid JSON can be demoted because unrelated HTML appeared elsewhere | 7 |
| EVID-01 | Caller-supplied observed findings lack artifact binding | Evidence grade can be asserted without durable source provenance | 5 |

### 2.2 Execution reliability

| ID | Verified issue | Current consequence | Owning phase |
|---|---|---|---|
| EXEC-01 | Artifact metadata/body framing can reorder | Reads can return empty or malformed content | 2 |
| EXEC-02 | Artifact reader loads entire file before slicing | Pagination does not scale to large files | 2 |
| EXEC-03 | Catalog/shell output is capped before artifact fallback | “Full artifact” may already be truncated | 2 |
| EXEC-04 | Explicit Nmap `ports` may be ignored | User intent can silently become `-F` | 2 |
| EXEC-05 | Alias resolution may not reach the command builder | An alias can resolve registry metadata but fail execution | 2 |
| EXEC-06 | Runtime shell allowlist can drift from JSON config | Displayed configuration may not match actual enforcement | 2 |
| SHELL-01 | Raw redirects are blocked without structured alternatives | Safe stderr merge/output-file use cases are awkward | 2 |
| FAN-01 | Fanout executes sequentially | Large batches provide no actual parallel speedup | 3 |

### 2.3 Job and attempt truth

| ID | Verified issue | Current consequence | Owning phase |
|---|---|---|---|
| JOB-01 | Jobs are process-local | Backend restart loses job and result state | 3 |
| JOB-02 | No job cancellation endpoint | Stuck work has no supported escape | 3 |
| JOB-03 | No process-group cleanup/reaping guarantee | Timeout can leave work running | 3 |
| JOB-04 | No partial-output API | Operator cannot inspect a long scan while it runs | 3 |
| JOB-05 | No lease/heartbeat/reconciliation | Restart cannot distinguish running from orphaned work | 3 |
| ATT-01 | Tool coverage overwrites `(engagement, tool, asset)` | `platform_attempts` is latest state, not execution history | 3 |
| ATT-02 | Parameters, command, cache identity, and artifacts are missing | LLM cannot distinguish an identical rerun from a new experiment | 3 |

### 2.4 Findings and recall integrity

| ID | Verified issue | Current consequence | Owning phase |
|---|---|---|---|
| FIND-01 | Parser and YAML ingest can store the same fact twice | Counts and downstream ranking can inflate | 4 |
| FIND-02 | Re-merging a finding ID can increment engagement count | Summary counters can diverge from stored rows | 4 |
| FIND-03 | Store-time port-flood downgrade is batch-local | One-at-a-time writes avoid retrospective demotion | 4 |
| DELTA-01 | Context delta is global process memory | Restarts and multiple callers produce misleading deltas | 4 |
| SEARCH-01 | Memory search is linear, biased, and unpaged | Findings can crowd graph hits; large memory is hard to navigate | 4 |
| FIND-04 | Finding-summary behavior lacks explicit contract metadata | Empty, truncated, or run-filtered output is hard to diagnose | 4 |

### 2.5 Graph and evidence integrity

| ID | Verified issue | Current consequence | Owning phase |
|---|---|---|---|
| GRAPH-01 | Service and technology nodes are disconnected | Graph cannot answer where a service/technology was observed | 5 |
| GRAPH-02 | URL/host/IP canonicalization is weak | Equivalent assets can split into separate nodes | 5 |
| GRAPH-03 | Edge table has no evidence/provenance metadata | Supporting finding must be inferred indirectly | 5 |
| GRAPH-04 | Relation truncation can collide | Different long relation names can become one edge identity | 5 |
| GRAPH-05 | Reserved structural names are not protected | Operator links can imitate automatic structural edges | 5 |
| DAG-01 | Child evidence traversal is one level only | Descendant claims are omitted | 5 |
| DAG-02 | Parent IDs are not validated at write time | Missing or cross-engagement references can be stored | 5 |
| DAG-03 | Prefix lookup can be ambiguous | Wrong finding can be selected | 5 |

### 2.6 Correlation and ranking integrity

| ID | Verified issue | Current consequence | Owning phase |
|---|---|---|---|
| CORR-01 | Correlation automatically writes generic hypothesis links | LLM cannot accept, reject, rename, or inspect candidate provenance first | 6 |
| CORR-02 | Correlations omit source finding IDs | Evidence cannot be traced through `derived_from` | 6 |
| CORR-03 | Correlation reruns create duplicate relation findings | Memory grows with repeated equivalents | 6 |
| SCORE-01 | Operator boost is counted from node and finding | `boost=40` can contribute 80 | 6 |
| SCORE-02 | Duplicate findings repeatedly add role/evidence points | Score measures row volume as much as importance | 6 |
| SCORE-03 | Score lacks component transparency and versioning | Ranking changes are difficult to audit | 6 |

### 2.7 Configuration and deployment

| ID | Verified issue | Current consequence | Owning phase |
|---|---|---|---|
| CFG-01 | Config browsing may prefer JSON while runtime prefers YAML | LLM can inspect stale rules | 8 |
| CFG-02 | Cached loaders have inconsistent reload behavior | Runtime changes require unclear restart/reload steps | 8 |
| CFG-03 | Safe runtime preferences are not layered or source-labeled | Engagement tuning requires global file edits | 8 |
| DEPLOY-01 | MCP and backend can run different route versions | New tools fail as generic HTTP 404 | 9 |
| DEPLOY-02 | No full wrapper-to-route contract test | API/MCP drift reaches live testing | 9 |

---

## 3. Cross-cutting contracts

Define contracts before changing behavior. Avoid returning unrelated dictionaries
whose fields drift between execution paths.

### 3.1 `ExecutionAttempt`

Append-only durable record:

```text
id
engagement_id
run_id
job_id?
kind = catalog | shell | script | fanout
requested_tool
resolved_tool
requested_params_redacted
normalized_params_redacted
requested_additional_args_redacted
effective_argv_redacted
request_fingerprint
cache_key?
cache_hit
force_refresh
timeout_seconds
policy_hash
status
created_at
started_at?
finished_at?
exit_code?
success?
finding_ids[]
stdout_artifact_id?
stderr_artifact_id?
error_class?
error_summary?
```

Rules:

- Immutable request identity after start.
- Status transitions are appended or audited.
- Secrets are redacted before persistence.
- `request_fingerprint` must be stable for semantically identical requests.
- `tool_coverage` becomes a rebuildable projection of executions.

### 3.2 `ExecutionHandle`

Generic runtime interface:

```text
start(request) -> handle
poll(handle) -> progress
read_output(handle, stream, offset, limit) -> ArtifactSlice
cancel(handle, reason) -> state
reconcile(handle) -> state
```

Use this for tools, shell, scripts, and fanout branches. Do not add a different
job engine for each scanner.

### 3.3 `ArtifactRecord` and `ArtifactSlice`

```text
ArtifactRecord:
  id
  engagement_id
  execution_id
  stream = stdout | stderr | combined | custom
  canonical_path
  media_type
  encoding
  size_bytes
  sha256
  created_at
  completed

ArtifactSlice:
  artifact_id
  offset
  end
  returned_bytes
  total_bytes
  content
  encoding
  eof
  next_offset?
```

### 3.4 `ContextCursor`

```text
cursor
engagement_id
consumer_id
created_at
absolute_counts
changes_since_previous
latest_finding_id?
latest_execution_id?
latest_graph_event_id?
```

Reading a delta must not globally consume changes for other clients.

### 3.5 `EvidenceCandidate`

```text
id
fingerprint
engagement_id
candidate_type
source_asset
target_asset?
suggested_relation?
contributing_finding_ids[]
quoted_excerpts[]
positive_features[]
negative_features[]
confidence
rationale
required_confirmation
rule_id
rule_version
status = pending | accepted | rejected | superseded
decision_actor?
decision_reason?
accepted_relation_finding_id?
```

### 3.6 `EffectivePolicy`

```text
policy_hash
platform_version
sources[]
values
locked_fields[]
warnings[]
validation_errors[]
```

Resolution order:

```text
platform defaults
  → named profile
  → engagement-safe preferences
  → permitted per-call values
```

Safety fields may only become stricter through ordinary LLM calls.

---

## 4. Phase 0 — Baseline, tracker, and contract tests

### Goal

Create a trustworthy baseline before migrations and behavior changes.

### Work

1. Add `docs/PLATFORM_RELIABILITY_TRACKER.md`.
2. Enter every issue ID from Section 2 with:
   - Reproducer
   - Current result
   - Expected result
   - Owning phase
   - Test name
   - Status
3. Add schemas for the contracts in Section 3 without switching production
   behavior yet.
4. Capture current OpenCode reproducers:
   - Empty artifact body
   - Explicit Nmap ports ignored
   - Job survives longer than caller but cannot cancel
   - Restart loses job state
   - Attempt parameters missing
   - Context delta repeatedly zero
   - Child evidence traversal incomplete
   - Mixed HTML/JSON SPA demotion
   - Asset tag boost counted twice
   - Gated tool approved
5. Record current database and Docker behavior as fixtures.

### Primary files

- `backend/src/pentest_platform/schemas/tools.py`
- `backend/src/pentest_platform/schemas/jobs.py`
- New `backend/src/pentest_platform/schemas/executions.py`
- New `backend/src/pentest_platform/schemas/artifacts.py`
- New `backend/src/pentest_platform/schemas/policy.py`
- `platform-mcp/server.py`
- `backend/tests/`

### Acceptance

- Every issue has a failing or characterization test.
- Contract schemas serialize and validate independently.
- No production behavior has changed.
- Existing Phase 1–7 focused tests still pass.

### Recommended PR

`reliability/phase-0-contracts`

---

## 5. Phase 1 — Make the referee truthful

### Goal

Enforce the safety boundaries the documentation already claims.

### 5.1 Governance decisions

Replace unconditional approval in `GovernanceEngine.check()` with typed policy
evaluation:

```text
registered tool?
  → active engagement?
  → target within engagement scope?
  → category/safety level permitted?
  → rules of engagement permit requested capability?
  → required operator approval present?
  → scan-budget policy permits normalized request?
  → approve or reject with decision record
```

Do not create a fixed tool sequence. Evaluate whether a chosen experiment is
authorized.

Decision response:

```text
allowed
decision_id
policy_hash
matched_rules[]
blocked_by[]
requires_approval
explanation
```

Persist governance decisions with the execution attempt.

### 5.2 Gated tools

For `ToolSafetyLevel.GATED`:

- Require a durable, scoped approval.
- Approval names the engagement, capability category, actor, reason, and expiry.
- A generic chat phrase must not silently unlock every gated tool.
- Expired or mismatched approval rejects execution.

### 5.3 Script scan budget

Scripts are intentionally flexible, so do not attempt fragile source-code
keyword blocking.

Use runtime boundaries:

- Network namespace/target scope controls where possible.
- Maximum process duration and resource limits.
- Optional declared intent/capabilities in script request.
- Outbound target observation and post-execution audit.
- For recognized scanner invocations, apply the same wide-range confirmation
  contract as catalog/shell.
- Destructive/exploitation capability requires explicit scoped permission.

The objective is not to predict every script. It is to enforce scope and
resource policy around arbitrary experiments.

### 5.4 Rules of engagement

Compile stored engagement rules into typed policy fields where possible:

- Allowed domains, IPs, CIDRs, ports
- Excluded assets
- Allowed hours
- Request-rate ceiling
- Exploitation permission
- Credential-use permission
- Destructive-action prohibition

Keep free-form text for human context, but do not pretend free-form text alone
is machine enforcement.

### Primary files

- `backend/src/pentest_platform/services/governance.py`
- `backend/src/pentest_platform/services/scan_budget.py`
- `backend/src/pentest_platform/services/script_exec.py`
- `backend/src/pentest_platform/services/tool_execution.py`
- `backend/src/pentest_platform/services/shell_exec.py`
- Engagement policy schemas/models
- `platform-mcp/server.py`

### Tests

- Registered safe tool within scope is allowed.
- Out-of-scope target is rejected.
- Gated tool without approval is rejected.
- Correct scoped approval is allowed and persisted.
- Approval for another engagement is rejected.
- Expired approval is rejected.
- Script resource and target boundaries are enforced.
- Governance decision appears in execution provenance.

### Exit criteria

- No registered tool receives unconditional approval.
- `GATED` has runtime meaning.
- Catalog, shell, and script all pass through one effective policy boundary.
- Existing flexible `additional_args` remain available when authorized.

### Recommended PRs

1. `reliability/phase-1-policy-model`
2. `reliability/phase-1-governance-enforcement`
3. `reliability/phase-1-script-boundary`

---

## 6. Phase 2 — Correct execution identity and artifacts

### Goal

Execute exactly what the operator requested, or return a clear ambiguity error;
preserve uncapped output before formatting.

### 6.1 Artifact transport

Replace mixed text/binary framing.

Preferred backend behavior:

```python
with open(path, "rb") as stream:
    stream.seek(offset)
    chunk = stream.read(limit)
```

Return metadata as JSON outside the raw content channel. For binary output:

- Detect invalid UTF-8.
- Return `encoding=base64` when requested or required.
- Never derive byte offsets from a replacement-decoded string.

Validation:

- Resolve canonical workdir.
- Resolve candidate path.
- Reject path if it escapes the workdir.
- Reject symlink escape.
- Return explicit `not_found`, `offset_past_eof`, and `incomplete_artifact`
  errors.

### 6.2 Uncapped spooling

For catalog, shell, and script:

```text
child stdout/stderr
  → stream directly to artifact files
  → maintain byte counters
  → optionally retain bounded preview in memory
  → parse bounded or streamed content
  → MCP card receives preview only
```

Do not create the “full” artifact from an already truncated response.

### 6.3 Canonical tool resolution

Resolve aliases once:

```text
requested_tool
  → registry canonical name
  → command builder module
  → execution adapter
  → parser
  → coverage/execution record
```

Persist both requested and resolved names. All later stages use the canonical
name.

### 6.4 Nmap port selector

Build tokenized argv, not an opaque flag string.

Recognize selectors from:

- Typed `ports`
- `flags`
- `additional_args`

Rules:

```text
ports="22,443" → -p 22,443
no selector supplied → tool-specific safe default such as -F
one equivalent selector repeated → deduplicate
conflicting selectors → reject with ambiguity error
full range → require expensive-scan confirmation/policy
```

Never silently replace an explicit selector with `-F`.

### 6.5 Structured shell

Introduce:

```text
stages:
  - argv: [...]
pipeline: true|false
stderr_mode: separate | merge | discard
stdout_artifact: true|false
stderr_artifact: true|false
```

Compatibility:

- Parse the existing simple command string into this request.
- Keep allowlisted binaries.
- Continue rejecting raw redirection, substitution, `&&`, backgrounding, and
  device paths.
- Output destinations are artifact IDs, not arbitrary filesystem syntax.

### 6.6 Allowlist source of truth

Choose one runtime source:

- Prefer validated YAML/JSON loaded by the enforcement service, or
- Generate documentation/config output from the Python source.

Do not maintain two independently editable lists.

### Primary files

- `backend/src/pentest_platform/services/artifacts.py`
- `backend/src/pentest_platform/services/mcp_client.py`
- `backend/src/pentest_platform/services/command_builder.py`
- `backend/src/pentest_platform/services/param_validator.py`
- `backend/src/pentest_platform/services/shell_exec.py`
- `backend/src/pentest_platform/services/tool_execution.py`
- `platform-mcp/typed_recon_network.py`
- `platform-mcp/server.py`

### Tests

Artifacts:

- Small UTF-8 file.
- Multi-megabyte file.
- Binary file.
- Slice at zero, middle, EOF, and beyond EOF.
- UTF-8 boundary split.
- Missing file.
- Traversal and symlink escape.
- Running/incomplete artifact.

Execution:

- Alias reaches canonical builder/parser.
- `ports="22,443"` produces exact argv.
- Duplicate equivalent selector is normalized.
- Conflicting selectors return a diagnostic.
- Default `-F` applies only with no selector.
- Full-range request reaches governance.
- Separate, merged, and discarded stderr work without raw redirection.
- Runtime allowlist equals displayed config.

### Exit criteria

- Artifact content is preserved before card truncation.
- Pagination reads only the requested byte range.
- Operator port intent is never silently changed.
- Safe shell output controls cover the legitimate `2>&1` use case.

### Recommended PRs

1. `reliability/phase-2-artifacts`
2. `reliability/phase-2-command-identity`
3. `reliability/phase-2-structured-shell`

---

## 7. Phase 3 — Durable executions, jobs, cancellation, and concurrency

### Goal

Make execution history and long-running work survive backend restarts.

### 7.1 Database migrations

Add append-only `executions`.

Add durable `jobs`:

```text
id
execution_id
engagement_id
run_id
kind
label
status
lease_owner?
lease_expires_at?
heartbeat_at?
cancel_requested_at?
cancel_reason?
created_at
started_at?
finished_at?
error_class?
error_summary?
```

Add artifact records or durable references.

Do not delete `tool_coverage` immediately. Rebuild/update it as a derived
projection until all consumers move to executions.

### 7.2 Job state machine

```text
queued
  → running
  → completed
  → failed
  → cancel_requested → cancelled
  → interrupted
```

Transitions must be validated. Completion after cancellation request must record
the race explicitly rather than silently rewriting history.

### 7.3 Process ownership and cleanup

Every running execution needs an identifiable process group, container, or
equivalent executor handle.

On timeout or cancel:

```text
mark cancel_requested
  → send TERM
  → wait configured grace period
  → send KILL if still alive
  → await/reap process
  → close artifact streams
  → persist final status and offsets
```

### 7.4 Heartbeats and reconciliation

Worker:

- Claims queued job with lease.
- Renews heartbeat.
- Writes progress and artifact offsets.

Startup:

- Find `running` jobs with expired leases.
- Ask executor adapter whether work still exists.
- Reattach when identity is proven.
- Otherwise mark `interrupted`.

Never report a stale job as running indefinitely.

### 7.5 Partial output and explicit APIs

Add:

- `GET /jobs`
- `GET /jobs/{id}`
- `GET /jobs/{id}/output?stream=stdout&offset=...`
- `POST /jobs/{id}/cancel`
- MCP `platform_job_list`
- MCP `platform_job_cancel`
- MCP `platform_job_output`

Keep `platform_job_poll(job_id)` for status polling. Empty polling may remain
backward-compatible but should no longer be the only way to discover listing.

### 7.6 Attempt history

Move `platform_attempts` to `executions` and return:

- Execution/job IDs
- Requested and resolved tool
- Normalized redacted parameters
- Effective redacted argv
- Request fingerprint
- Cache identity/hit
- Timeout
- Start/end/duration
- Status/exit code
- Finding IDs
- Artifact IDs
- Policy hash

History remains advisory.

### 7.7 Fanout concurrency

Use the same job/executor infrastructure:

- Explicit asset shortlist.
- Bounded concurrency from effective policy.
- One child execution per asset.
- Parent fanout execution tracks children.
- Partial results remain visible if another child fails.
- Cancellation can stop parent and active children.

Do not auto-fanout from an open gap.

### Primary files

- New Alembic migration
- New execution/job SQLAlchemy models
- `backend/src/pentest_platform/services/job_store.py`
- `backend/src/pentest_platform/services/mcp_client.py`
- `backend/src/pentest_platform/services/fanout.py`
- `backend/src/pentest_platform/services/fanout_assets.py`
- `backend/src/pentest_platform/services/tool_coverage_store.py`
- `backend/src/pentest_platform/services/operator_recall.py`
- `backend/src/pentest_platform/api/v1/endpoints/jobs.py`
- `backend/src/pentest_platform/schemas/jobs.py`
- `platform-mcp/server.py`

### Tests

- Job survives backend restart.
- Completed job result remains available.
- Cancel terminates and reaps process.
- Timeout terminates and reaps process.
- Partial stdout can be read while running.
- Expired lease becomes interrupted.
- Reconciliation reattaches only with proven identity.
- Four concurrent jobs obey configured cap.
- Fanout respects bounded concurrency.
- One fanout child failure does not discard other results.
- Attempts retain two runs of the same tool/asset with different parameters.
- Secret values are redacted.

### Exit criteria

- No authoritative job state lives only in a Python dictionary.
- Every execution has durable identity.
- Long work can be cancelled, inspected, and reconciled.
- `platform_attempts` is true append-only history.

### Recommended PRs

1. `reliability/phase-3-execution-ledger`
2. `reliability/phase-3-job-runner`
3. `reliability/phase-3-job-api`
4. `reliability/phase-3-fanout-concurrency`

---

## 8. Phase 4 — Findings, counters, deltas, and search integrity

### Goal

Make memory counts and recall reflect durable facts rather than parser volume or
global process state.

### 8.1 Semantic finding fingerprint

Add a stable fingerprint derived from normalized:

```text
engagement_id
finding_type
canonical asset/target
normalized title/category
source evidence identity
```

Do not globally merge every similar title. Support two concepts:

- **Occurrence** — one parser/execution observed something.
- **Canonical finding** — semantic fact grouping related occurrences.

Preserve all occurrences for provenance while preventing repeated parser paths
from multiplying one logical finding in summaries and scores.

### 8.2 Parser/YAML duplicate handling

During one execution:

- Compare deterministic/free-form/YAML promoted fingerprints.
- Attach multiple parser origins to one canonical finding.
- Prefer the strongest valid grade only when supporting evidence justifies it.
- Never upgrade merely because two weak parsers agreed.

Across executions:

- Link new occurrence to existing canonical finding.
- Preserve timestamps and execution IDs.
- Make recurrence count visible.

### 8.3 Engagement counters

Replace blind increment-on-merge with one of:

- Database count query/projection, or
- Insert-only counter update using affected-row semantics.

Add reconciliation command/test:

```text
stored engagement findings_count
==
count(canonical findings or defined occurrence metric)
```

Document which metric the field represents.

### 8.4 Cumulative port-flood classification

Move classification to a rebuildable host-evidence projection:

```text
all port occurrences for host
all service/banner occurrences for host
classification version
classification reason
```

Do not mutate historical evidence destructively. Store a current classification
or derived tag and let finalize consume it.

### 8.5 Durable context cursors

Replace `snapshot_counts()` consume-on-read behavior.

API:

```text
platform_context(cursor=<optional>)
```

Response:

```text
absolute_counts
changes_since_cursor
new_cursor
cursor_scope
truncated
```

Cursor scope includes engagement and consumer. One client cannot consume another
client’s delta.

### 8.6 Findings-summary contract

Always return:

```text
engagement_id
run_scope
count
returned_count
truncated
generated_at
summary
finding_ids[]
```

Zero findings is a valid explicit response, not an empty/missing field.

### 8.7 Search

Add pagination and balanced result groups:

```text
findings[]
graph_nodes[]
executions[]
next_cursor?
```

Start with PostgreSQL full-text/trigram or normalized substring indexes rather
than an external search service unless measured scale requires one.

Support:

- Kind filters
- Grade/severity/type filters
- Source tool
- Asset
- Time range
- Exact finding/execution ID

Search remains retrieval, not a recommendation engine.

### Primary files

- Finding models and Alembic migration
- `backend/src/pentest_platform/services/findings_store.py`
- `backend/src/pentest_platform/services/summary_agent.py`
- `backend/src/pentest_platform/services/ingest_promoter.py`
- `backend/src/pentest_platform/services/evidence.py`
- `backend/src/pentest_platform/services/context_delta.py`
- `backend/src/pentest_platform/services/commander_context.py`
- `backend/src/pentest_platform/services/operator_recall.py`
- Findings API/MCP wrappers

### Tests

- Same execution parsed by two paths produces one canonical finding with two
  origins.
- Repeated execution preserves two occurrences.
- Weak duplicates do not become observed.
- Merging an ID does not overcount.
- Reconciliation repairs a deliberately wrong counter.
- Forty one-at-a-time ports trigger cumulative flood classification.
- Two context consumers receive independent deltas.
- Backend restart preserves cursor behavior.
- Search paginates and does not let findings eliminate graph/execution groups.
- Exact ID search is deterministic.

### Exit criteria

- Counts are defined and reconcilable.
- Duplicate parser output does not inflate logical findings or rankings.
- Delta behavior is durable and per consumer.
- Memory search can navigate large engagements predictably.

### Recommended PRs

1. `reliability/phase-4-finding-identity`
2. `reliability/phase-4-counters-classification`
3. `reliability/phase-4-context-cursors`
4. `reliability/phase-4-search`

---

## 9. Phase 5 — Graph schema and evidence DAG

### Goal

Make graph identity and evidence provenance explicit without turning the graph
into a mandatory attack-path engine.

### 9.1 Canonical assets

Create type-specific normalization:

Host/domain:

- Lowercase
- Remove trailing dot
- Normalize IDNA/punycode
- Validate labels

IP:

- Use standard IP parser
- Canonicalize IPv4/IPv6

URL:

- Parse with standard library
- Lowercase scheme/host
- Normalize default ports
- Normalize path safely
- Define query sorting policy
- Preserve original observed form in aliases

Port:

- `(canonical host/IP, protocol, integer port)`

Keep:

```text
canonical_label
observed_aliases[]
```

Add migration/reconciliation for existing duplicate nodes. Produce a merge
report before mutating data.

### 9.2 Complete automatic topology

Add evidence-backed structural links:

```text
service --detected_on--> port
technology --detected_on--> host|url
subdomain --under_domain--> domain
finding/execution provenance through edge record, not as graph nodes unless needed
```

Only create links when parser metadata identifies the endpoint. Do not guess a
host from a broad seed target.

### 9.3 Edge provenance

Extend edge storage or add `edge_evidence`:

```text
edge_id
finding_id
execution_id?
evidence_grade
created_at
run_id
source = automatic | operator | accepted_candidate
```

One structural edge may have multiple evidence rows.

Keep topology identity separate from evidence occurrences.

### 9.4 Relation namespace

Separate:

- Reserved structural relations controlled by projector.
- Operator-authored semantic relations.
- Hypothesis relations.

Do not silently truncate into collisions. Options:

- Reject overlong names with clear limit, or
- Store full canonical relation and separate display label.

### 9.5 Evidence DAG

At write time:

- Require exact finding IDs.
- Validate same engagement.
- Reject missing parents.
- Reject direct cycles.
- Attach execution/artifact provenance automatically for parsed findings.

Traversal:

```text
direction = ancestors | descendants | both
depth = 1..configured max
exact root ID
cycle detection
distance
path
truncated
missing references
```

Build reverse adjacency through indexed database queries or a durable relation
table rather than scanning 5,000 rows for every request.

### 9.6 Grade semantics

Do not automatically propagate evidence grade through DAG edges.

Return:

- Grade of each node.
- Grade of supporting parents.
- A warning when a claim grade exceeds supporting evidence.

Promotion remains an explicit new finding or operator decision.

### Primary files

- Graph/finding models and Alembic migration
- `backend/src/pentest_platform/services/engagement_graph.py`
- `backend/src/pentest_platform/services/operator_memory.py`
- `backend/src/pentest_platform/services/evidence_chain.py`
- `backend/src/pentest_platform/services/operator_recall.py`
- `backend/src/pentest_platform/services/graph_query.py`
- Parsers that supply endpoint metadata

### Tests

- Equivalent URL/host/IP forms resolve to one canonical node.
- Original aliases remain inspectable.
- IPv6 works.
- Service links to correct port.
- Technology links only with endpoint evidence.
- Structural namespace cannot be impersonated by operator relation.
- One edge retains multiple evidence rows.
- Duplicate long relation names cannot collide silently.
- Cross-engagement parent is rejected.
- Missing parent is rejected.
- Ancestor and descendant traversal both reach requested depth.
- Cycles are reported safely.
- Exact IDs replace ambiguous prefix selection.

### Exit criteria

- Graph can answer “where was this service/technology observed?”
- Edge evidence is directly queryable.
- Asset identity is canonical and aliases are preserved.
- Evidence traversal is complete, exact, and engagement-safe.

### Recommended PRs

1. `reliability/phase-5-asset-canonicalization`
2. `reliability/phase-5-edge-provenance`
3. `reliability/phase-5-evidence-dag`

---

## 10. Phase 6 — Correlation candidates and ranking integrity

### Goal

Let automation discover patterns while the LLM owns interpretation.

### 10.1 Candidate-first correlation

Change correlator output from automatic graph writes to `EvidenceCandidate`
records.

Example:

```text
candidate_type=shared_cookie_domain
source_asset=portal.example
target_asset=admin.example
suggested_relation=shares_auth
contributing_finding_ids=[...]
quoted_excerpts=["Set-Cookie: ... Domain=.example.com"]
positive_features=["same cookie domain"]
negative_features=["session replay not tested"]
confidence=0.62
required_confirmation="Verify whether one session authenticates both apps"
```

### 10.2 LLM decision operations

Add:

- List candidates
- Inspect candidate
- Accept with relation name/evidence grade
- Reject with reason
- Rename
- Mark superseded
- Request/deepen confirmation

Accept:

```text
candidate
  → platform_graph_link
  → derived_from=contributing finding IDs
  → candidate status=accepted
  → store resulting relation finding ID
```

Reject:

- Persists decision.
- Same unchanged fingerprint does not reappear.
- New evidence/version may create a new candidate.

### 10.3 Incremental/idempotent correlation

Fingerprint:

```text
rule_id
rule_version
canonical source/target
sorted contributing finding fingerprints
material feature values
```

Run only for new/changed evidence rather than rescanning the latest 2,000
findings after every ingest.

### 10.4 Fix crown-jewel boost

Choose one source of operator boost:

- Prefer canonical asset-priority record or node metadata.
- Tag finding remains audit history but does not add score again.

Add an exact test:

```text
base_score = X
tag boost = 40
new_score = X + 40
```

### 10.5 Deduplicated score inputs

Score canonical facts/components, not raw finding rows.

Possible component model:

```text
role_component
evidence_component
severity_component
operator_component
technical_signal_component
graph_component?  # only if later justified and transparent
```

For each component return:

```text
name
points
source finding IDs
rule/profile version
reason
```

Repeated equivalent evidence should increase recurrence/support metadata, not
re-add full points indefinitely.

### 10.6 Preserve flexibility

- Scores remain advisory.
- No score threshold starts a tool.
- LLM can add a bounded, reasoned priority adjustment.
- Business meaning remains in operator role/relation names.
- Configuration controls weights, not workflow order.

### Primary files

- New evidence-candidate model/migration
- `backend/src/pentest_platform/services/finding_correlator.py`
- `backend/src/pentest_platform/services/operator_memory.py`
- `backend/src/pentest_platform/services/crown_jewels.py`
- `backend/src/pentest_platform/services/hypothesis_engine.py`
- `config/correlation_rules.yaml`
- `config/thinking_model.yaml`
- Candidate API/MCP wrappers

### Tests

- Correlation emits candidate without graph mutation.
- Candidate includes exact source IDs and excerpts.
- Accept creates one relation with `derived_from`.
- Reject remains durable.
- Unchanged candidate does not reappear.
- New evidence creates a new version/fingerprint.
- `boost=40` contributes exactly 40.
- Duplicate finding occurrences do not multiply score.
- Score output explains every point.
- No candidate or score triggers execution.

### Exit criteria

- Automatic inference is provenance-rich and reversible.
- The LLM authors accepted relation meaning.
- Ranking is deterministic, explainable, and not row-count inflated.

### Recommended PRs

1. `reliability/phase-6-candidate-model`
2. `reliability/phase-6-candidate-decisions`
3. `reliability/phase-6-ranking-integrity`

---

## 11. Phase 7 — Response-scoped HTTP and SPA classification

### Goal

Classify each HTTP response independently and require corroboration before
calling it a catch-all.

### 11.1 HTTP response envelope

Parsers should emit:

```text
request_url
requested_path
method
status
content_type
headers
body_artifact_id
body_preview
body_sha256
body_length
parsed_body_type = json_object | json_array | html | text | binary | unknown
source_execution_id
source_finding_id?
```

### 11.2 Strong JSON/API evidence

Recognize:

- JSON object
- JSON array
- Valid JSON with suffix parameters in content type
- Problem JSON
- GraphQL JSON response

Do not require `{` only.

### 11.3 Catch-all corroboration

HTML is a candidate signal, not proof.

Compare API-looking response with:

- Random nonexistent path, and/or
- Root response, and/or
- Configured baseline path.

Features:

- Status
- Content type
- Body hash/signature
- Stable title/root marker
- Length similarity
- Redirect destination

Classify catch-all only when configured corroboration threshold is met.

### 11.4 Scoped demotion

Demote only the affected response/claim.

Mixed output:

```text
/api/users → valid JSON
/swagger → SPA HTML
```

must preserve the observed JSON finding while marking only `/swagger` as
catch-all suspect.

### 11.5 Finalize integration

Finalize consumes structured classification:

```text
response.classification=spa_catchall
classification_confidence
corroborating_response_ids
```

Keep conservative blocking for a high/critical claim based on a confirmed
catch-all.

### Primary files

- New HTTP response schema
- Relevant HTTP parsers
- `backend/src/pentest_platform/services/ingest_promoter.py`
- `backend/src/pentest_platform/services/finalize_readiness.py`
- `config/ingest_rules.yaml`
- New typed HTTP evidence profile

### Tests

- Ordinary HTML page is not automatically an API.
- Valid JSON object is observed.
- Valid JSON array is observed.
- Mixed JSON and HTML are classified independently.
- Express/React SPA catch-all is corroborated.
- GraphQL IDE HTML is not confused with GraphQL JSON.
- Redirect catch-all is detected.
- Finalize blocks only the affected false claim.

### Exit criteria

- No whole-output SPA flag demotes unrelated responses.
- Catch-all classification contains corroborating response IDs.
- JSON arrays and valid structured responses receive correct evidence treatment.

### Recommended PR

`reliability/phase-7-response-classification`

---

## 12. Phase 8 — Layered configuration and audited report decisions

### Goal

Make runtime behavior inspectable and tunable without exposing safety controls to
ordinary LLM mutation.

### 12.1 One configuration source of truth

For each config family:

- Prefer YAML.
- Remove or generate legacy JSON mirrors.
- `platform_config` must display the same effective source used by runtime.
- Return source path, version, loaded timestamp, and hash.

### 12.2 Loader registry

Create a consistent config registry:

```text
load(name)
validate(name)
effective(name, engagement_id?)
reload(name, actor)
version(name)
```

Reload:

- Validates before swap.
- Is atomic.
- Preserves previous config on failure.
- Writes an audit event.

### 12.3 Safe engagement preferences

Operator-confirmed, non-safety preferences may include:

- Context display limits
- Report-outline section size
- Soft background suggestion threshold
- Correlation profile selection
- Search page size within bounds

Ordinary calls may not weaken:

- Scope
- Command allowlist
- Gated approvals
- Scan budget
- Maximum actual concurrency
- Claim-integrity blockers

### 12.4 Finalize decision record

Replace raw ephemeral `override=true` with:

```text
FinalizeDecision:
  id
  engagement_id
  actor
  reason
  created_at
  expires_at?
  policy_hash
  original_blockers[]
  overridden_blockers[]
  non_overridable_blockers[]
  resulting_report_mode
```

Config defines overridable blocker classes.

Recommended rule:

- Inventory completeness blockers may be overridden.
- Unsupported HIGH/CRITICAL, weak CVE, and confirmed SPA false-API claim
  integrity remain non-overridable without an explicit higher-trust admin policy.

Context and report outline show both original blockers and decision.

### Primary files

- `backend/src/pentest_platform/services/knowledge_browser.py`
- `backend/src/pentest_platform/services/parallelism_config.py`
- `backend/src/pentest_platform/services/finalize_rules.py`
- `backend/src/pentest_platform/services/finalize_readiness.py`
- New policy/config registry
- New finalize-decision model/migration
- `platform-mcp/server.py`

### Tests

- Runtime and `platform_config` return the same YAML hash.
- Invalid reload preserves old config.
- Safe engagement preference shows its source.
- LLM cannot increase hard concurrency or weaken scan budget.
- Finalize decision requires actor and reason.
- Decision persists across restart.
- Expired decision no longer applies.
- Non-overridable claim-integrity blocker remains blocked.
- Report outline displays original blockers and decision record.

### Exit criteria

- Effective policy is explainable field by field.
- Runtime config reload is consistent and auditable.
- Finalize decisions are durable and bounded.

### Recommended PRs

1. `reliability/phase-8-config-registry`
2. `reliability/phase-8-effective-policy`
3. `reliability/phase-8-finalize-decisions`

---

## 13. Phase 9 — Deployment contracts and authorized dry run

### Goal

Prevent split-version deployment and prove the entire repaired system through
realistic use.

### 13.1 Version/capability handshake

Backend exposes:

```text
backend_version
schema_version
capabilities[]
route_contract_hash
minimum_mcp_version
```

MCP exposes its expected contract.

At startup:

- Compare versions and required capabilities.
- Fail a missing route before a user tool call.
- Return an actionable message:

```text
Backend/MCP capability mismatch.
Restart backend, reload MCP, or deploy matching versions.
Missing: memory-search, evidence-chain, attempts.
```

### 13.2 Contract suite

For every MCP wrapper:

- Expected API method/path
- Request schema
- Response schema
- Authentication/session behavior
- Error mapping
- Capability name

CI should start the Docker stack and invoke wrappers against the live OpenAPI
contract.

### 13.3 Durable artifact volume

Mount engagement artifacts on a durable Docker volume.

On startup:

- Reconnect artifact database records to files.
- Mark missing files explicitly.
- Never silently return empty content for a missing artifact.

### 13.4 Reliability and leak tests

Add tests for:

- Backend restart during job
- Kali restart during job
- Cancellation race
- Timeout kill/reap
- Process/container leak count
- Partial-output offsets
- Database migration upgrade/rollback strategy
- Secret redaction
- Artifact retention and cleanup policy

### 13.5 Authorized end-to-end dry run

Use only an owned/authorized target.

Exercise:

1. Bind target and inspect effective policy.
2. Run exact Nmap typed ports and verify argv.
3. Run structured shell with merged stderr.
4. Start a long job.
5. Read partial stdout.
6. Restart backend and reconcile job.
7. Cancel another job and verify process cleanup.
8. Inspect two complete execution attempts.
9. Search memory with pagination.
10. Compare independent context cursors.
11. Generate a correlation candidate.
12. Reject one candidate and accept/rename another.
13. Traverse evidence ancestors and descendants.
14. Validate mixed JSON/SPA response classification.
15. Apply an allowed finalize decision with reason.
16. Verify non-overridable claim-integrity blocker.
17. Generate report outline with provenance.

### Primary files

- Backend version/capability endpoint
- `platform-mcp/server.py`
- Docker Compose/volume configuration
- CI workflow
- Contract and integration tests
- `docs/PLATFORM_RELIABILITY_TRACKER.md`

### Exit criteria

- Stale backend/MCP mismatch is diagnosed before normal use.
- All MCP wrappers pass live contract tests.
- Jobs and artifacts survive expected restart scenarios.
- Tracker closes issues only with test and dry-run evidence.

### Recommended PRs

1. `reliability/phase-9-version-handshake`
2. `reliability/phase-9-contract-suite`
3. `reliability/phase-9-durable-artifacts`
4. `reliability/phase-9-authorized-dry-run`

---

## 14. Dependency order

Implement in this order:

```text
Phase 0 contracts
  ↓
Phase 1 governance
  ↓
Phase 2 artifact and command correctness
  ↓
Phase 3 durable executions/jobs
  ↓
Phase 4 finding identity/recall
  ↓
Phase 5 graph/evidence DAG
  ↓
Phase 6 correlation/ranking
  ↓
Phase 7 HTTP classification
  ↓
Phase 8 policy/finalize decisions
  ↓
Phase 9 contracts/dry run
```

Parallel work that is safe:

- Phase 7 HTTP response schemas can be prototyped after Phase 0.
- Phase 8 config registry can begin after Phase 1 policy schema stabilizes.
- Phase 9 handshake can begin early, but the complete dry run stays last.

Do not:

- Build candidate acceptance before exact evidence IDs exist.
- Build durable attempts before the execution schema is defined.
- Rewrite ranking before canonical finding identity is available.
- Claim durable artifacts before Docker volume and execution references exist.

---

## 15. Per-phase engineering checklist

Before coding:

- [ ] Link work to issue IDs in the tracker.
- [ ] Reproduce current behavior.
- [ ] Add failing test or explicit characterization test.
- [ ] Confirm whether migration is required.
- [ ] Define rollback/compatibility behavior.
- [ ] Identify secrets requiring redaction.

During coding:

- [ ] Use typed contracts.
- [ ] Preserve engagement isolation.
- [ ] Preserve raw evidence.
- [ ] Store effective normalized request.
- [ ] Return explicit errors instead of silent fallback.
- [ ] Keep suggestions advisory.
- [ ] Avoid per-tool special cases unless the tool protocol truly requires one.

Before merge:

- [ ] Focused unit tests pass.
- [ ] Backend integration tests pass.
- [ ] MCP-to-API test passes.
- [ ] Docker test passes.
- [ ] Migration tested from current database.
- [ ] No process/container leak.
- [ ] No sensitive value appears in logs or attempts.
- [ ] Documentation reflects implemented behavior.
- [ ] Tracker acceptance evidence attached.

---

## 16. Compatibility strategy

### Keep temporarily

- Existing `tool_coverage` table as a derived projection.
- Empty `platform_job_poll()` listing behavior.
- Simple shell command string parsed into structured shell request.
- Existing graph node IDs as aliases during migration.
- Legacy findings without execution/artifact references.

### Deprecate with visible warnings

- Attempt history sourced from tool coverage.
- Prefix finding-ID lookup.
- Process-local context delta.
- Raw `override=true`.
- JSON config mirrors.
- Claims that fallback artifacts always contain full output.

### Do not preserve

- Unconditional governance approval.
- Silent Nmap selector replacement.
- Double-counted operator boosts.
- Automatic graph mutation from correlation candidates.
- Ambiguous relation truncation.
- Cross-engagement or missing evidence parents.

---

## 17. Definition of done

The improvement program is complete when:

1. Every execution is durably identifiable and reconstructable.
2. Exact requested parameters and effective argv are visible after redaction.
3. Full stdout/stderr is spooled before UI truncation.
4. Jobs can be listed, inspected, cancelled, reaped, and reconciled.
5. Findings distinguish canonical fact from repeated occurrence.
6. Counts and crown scores are deterministic and reconcilable.
7. Graph assets are canonical and edge evidence is directly queryable.
8. Evidence traversal is exact and bidirectional.
9. Correlations are candidates the LLM can accept, reject, or rename.
10. HTTP classification is response-scoped and corroborated.
11. Governance enforces scope, gated approval, and effective policy.
12. Safe preferences are adjustable without weakening hard controls.
13. Finalize decisions are durable, reasoned, and bounded.
14. Backend/MCP version drift is detected before normal execution.
15. An authorized dry run proves all acceptance paths.

Most importantly:

> The repaired platform supplies truth, memory, safety, and capabilities. It
> still does not decide the engagement for the LLM.

