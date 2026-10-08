# Plan 21 — One Pentesting Harness: Methodology, Investigation and Honest Evidence

**Status:** Final planning proposal; implementation not started by this document.
**Date:** 2026-10-05
**Repository revision at writing:** `e2785ed`
**Risk:** High for runtime ownership and historical-data migration; deliver incrementally.
**Scope:** Architecture and implementation plan, not authorization to test external targets.

## 1. Decision and precedence

Build one persistent pentesting harness, with the CLI as its primary operator
interface. A deterministic methodology engine performs repeatable work; an LLM
investigates, reasons, and directs deeper work. They share one runtime, work queue,
execution lifecycle, evidence model, and reporting contract.

Neither the current architecture nor Plan 20 is a constraint on the solution.
Reuse sound components; replace or remove components whose responsibilities
overlap or whose contracts manufacture unsupported meaning. Do not preserve
multiple orchestration paths behind new wrappers.

This plan supersedes conflicting architectural recommendations in Plan 20 and
earlier harness plans, including this directory's historical README narrative.
Earlier documents remain historical analysis, not implementation authority where
they conflict with this plan. Existing runtime behavior is not changed by writing
this document. Update operator instructions alongside the eventual implementation.

### Required outcomes

- Routine applicable pentesting checks run without an LLM or API expenditure.
- The LLM remains an active investigator, not an end-of-run report writer.
- Individual tools, their purpose, progress, results and failures stay visible.
- The platform does not silently convert a source assertion into a stronger fact.
- Findings, asset identities, counts and coverage have explicit, testable meanings.
- Operators can extend methodology without adding another execution system.
- Runs survive interface disconnects and can resume without forgotten attempts.
- CLI, dashboard and external MCP clients access the same capabilities and state.

### Bounded guarantees

Identical recorded inputs, evaluation context and implementation/configuration
versions produce identical derived results, regardless of ingestion order.
Uncertainty and source attribution remain visible. All claims and report numbers
are traceable to stored records or explicit query definitions.

This is not a promise that software has no bugs, tools never lie, live rescans are
identical, humans are infallible, or every vulnerability will be found. A
deterministic wrong rule is still wrong. Positive and negative benchmark cases
must test correctness, not merely repeatability.

## 2. Target architecture: one owner, two decision sources

```text
CLI (primary) / Dashboard / MCP clients
                   |
             Shared runtime API
                   |
   Methodology engine ----+---- LLM / operator investigation
   (repeatable procedures)|     (reasoning and bespoke actions)
                          v
                One durable work queue
                          |
            Admission + scheduling + ownership
                          |
                 One execution lifecycle
                          |
          Tool adapters / browser / custom scripts
                          |
        Execution evidence + observations + check results
                          |
          Shared graph / context / coverage / reports
                          |
             New evidence informs both sources
```

Separate modules and concurrent workers are expected. Separate owners of the
same engagement's orchestration, private retry histories, or bypass execution
paths are not.

### Runtime ownership

Use one headless runtime implementation, hosted by the local backend for managed
runs. The CLI controls and observes it; the dashboard is another client, not a
second brain. Preserve CLI-first usability, interactive steering and visible
typed tool calls. Browser/CLI disconnect does not cancel a run implicitly.

Extract and reuse appropriate existing Runner/execution behavior; do not copy it
into a new server loop while leaving the old CLI loop active. LLM reasoning loops
and specialized workers run as managed runtime activities, not independent root
orchestrators. An external MCP agent can issue typed actions, but those actions
enter the same execution lifecycle and ledger.

Each run has one active execution owner enforced by durable ownership/lease
state. Background workers may execute different claimed work items concurrently.
Attach, detach, pause, resume and cancel have one definition across interfaces.

Do not promise exactly-once external execution. A crash after sending a request
but before persisting its result can leave execution uncertain. Reconcile an
existing process/job where possible; otherwise record an interrupted/unknown
outcome. Do not blindly rerun non-idempotent work.

### Common action lifecycle

1. Methodology, LLM or operator submits a typed action with immutable engagement,
   subject, provenance, parameters and relevant context/version references.
2. Runtime applies the same authorization, limits, deduplication and admission.
3. Scheduler claims the action and records execution before dispatch.
4. Executor emits visible start/progress/result events and stores raw evidence.
5. A supported adapter extracts narrowly defined observations and check results.
6. Derived views update; relevant new evidence enables further work.

Direct typed calls remain direct and visible. They are not routed through an
opaque multi-tool investigation macro. A multi-step check exposes every child
action through the same lifecycle and retains its prerequisites and results.

## 3. Keep, replace, remove and add

| Area | Decision |
|---|---|
| Tool execution, artifacts, existing database stores | Reuse after contract verification; consolidate writes through the shared lifecycle. |
| CLI interaction and typed tool surface | Keep; remove private orchestration ownership and divergent bookkeeping. |
| Expansion, tech dispatch, opportunity enumeration | Extract useful procedures into one check registry and scheduler; retire independent work-selection paths. |
| Deterministic/LLM/supervised drivers | Replace separate root execution paths with decision-source policies inside the same runtime. |
| Backend agent fallback | If retained, make it a managed worker using the same runtime, not a second root. |
| Recon/vuln/exploit phase unlocks | Replace execution gates with check prerequisites. Phases remain navigation, skills and reporting labels. |
| Priority and escalation systems | One explainable scheduling policy; preserve tool fallback procedures as check behavior, not another planner. |
| Retry/attempt history | One durable execution ledger, extending the existing scan-run store where practical. |
| Generic stdout-to-fact inference | Replace with explicit adapters; unsupported output is retained without forced classification. |
| Tool-count/evidence-label confidence promotion | Remove; use claim-specific validation and attributed assessments. |
| Title-substring false-positive suppression | Remove; use narrow, reversible, versioned claim-scoped suppression. |
| Graph, context and reports | Keep as evidence-backed projections, not independent truth-making layers. |
| Request/session collection and baseline comparisons | Add as shared harness capabilities, not standalone orchestration subsystems. |
| Dashboard | Thin runtime client; control and visualization follow runtime correctness. |

Re-check callers, public contracts and tests before deleting code. Preserve user
documents, presentations and study materials. Packaging cleanup is not deletion
of unrelated work.

## 4. Evidence and memory: precise contracts, not another scoring model

Use the existing persistence foundations wherever possible. These are logical
responsibilities, not a requirement to introduce separate databases or services.

### 4.1 Recorded execution

Retain the action, actual tool invocation, relevant input references, timestamps,
tool/check/adapter versions, outcome, stdout/stderr and request/response artifacts
where available. Evidence is append-preserving; corrections link to earlier
records rather than rewriting what happened. Retention and redaction must be
explicit: an unavailable/deleted artifact cannot still be presented as replayable.

### 4.2 Narrow observations and source assertions

An observation records what was measured or what a named source reported.
Those are distinguishable even when they concern the same asset.

Examples:

- An HTTP 501 establishes a recorded HTTP response; it does not establish the
  origin application, a technology version, or a vulnerability.
- A response advertising a server header establishes that header's presence;
  its software identity remains source-reported/fingerprinted unless established
  by an appropriate check.
- A wildcard DNS answer is retained with its wildcard context; it is not proof
  of a separately deployed application for every queried name.
- A reflected token establishes reflection, not executable XSS.
- Different response bodies establish a difference, not an authorization bypass.

Do not implement Plan 20's blanket prohibition on observations from 4xx/5xx/SPA
responses. Preserve useful narrow facts under every status. Conversely, a 2xx
response is not a universal affirmative signal.

Prefer structured tool formats: HTTPX JSONL, Nmap XML and supported scanner JSON.
Adapters validate schemas and keep field provenance. A page title must never be
guessed to be a technology because it occupies the final display-text bracket.
Structured output does not itself make a tool's inference true.

Unknown formats, malformed records and arbitrary shell/script output remain raw
evidence with an extraction outcome. Self-reported FINDING/REL records, including
LLM-authored scripts, are attributed assertions unless a registered validation
contract establishes something narrower. No `confirmed=true` output bypass.

### 4.3 Claims and validation results

An LLM, scanner or operator may propose a claim without proving it. Store its
author/source and investigation value; never relabel it as machine-established
merely because it has a genuine quotation or a confirming-sounding evidence kind.

Each supported validator defines a bounded predicate and records:

- Check identity/version and exactly what proposition was tested.
- Subject, parameters and relevant session/request context.
- Supporting execution/artifact references and necessary controls.
- Established, not established, or inconclusive result, with reason.

The generic platform checks identity, provenance, applicability and result
binding. Check-specific code tests the actual predicate. There is no universal
semantic-entailment engine for arbitrary finding titles and no second LLM whose
approval is treated as proof.

A successful registered check can establish its supported claim without an LLM.
Reports may show that result as check-validated. This is explicit validation,
not observation-count promotion, and must not require an LLM to author a finding
just to make the no-LLM report useful. Unsupported interpretations remain claims.

Remove automatic `two tools -> LIKELY` and `attestation -> CONFIRMED` rules.
Corroborating sources remain visible and useful for investigation; tool names do
not prove independence or claim applicability. Reflection/difference primitives
do not invent a medium severity.

Keep assessed impact separate from proof of existence. A validated reflection
cannot carry an unverified author's critical-impact label as a confirmed critical
finding. Preserve severity provenance and its supporting rationale; unsupported
impact remains explicitly claimed or unknown, without another numerical score.

Human confirmation is an attributed human assessment, distinguishable from a
check result. The agent cannot set human provenance through tool arguments. A
genuinely protected approval mechanism requires a trust boundary beyond hiding
an endpoint from MCP; a same-user shell/browser can otherwise reach it. Do not
advertise spoof-proof approval until that boundary exists and is tested.

### 4.4 Rechecks, suppression and historical data

Preserve historical results. Show "established on date; latest recheck
inconclusive" or "not reproduced on latest check" as appropriate. Unreachable,
changed prerequisites and active negative results are not interchangeable.
No failed recheck automatically means false positive or automatically becomes
LIKELY. Recheck applicability includes session and request context.

Suppression is a reversible operator decision scoped to a specific claim and
context, not proof of falsity. Changed relevant evidence can require review.
Never erase underlying evidence or silently suppress a different asset/parameter.

Migrate legacy confirmations with their original provenance. Preserve history,
but mark unsupported legacy evidence as not evaluated under the new contract;
never invent validation results or silently reaffirm old confidence labels.

### 4.5 Identity and numbers

Define canonical identity per entity, not by lowercasing arbitrary strings.
Normalize hostnames appropriately; preserve case-sensitive URL paths, parameter
values and meaningful request distinctions. Do not collapse vhosts because they
share an IP, or sessions because they reach the same URL. Separate canonical
facts from occurrences and raw-output changes. Version identity changes and
provide a migration map; do not destructively merge ambiguous historical rows.

Reports distinguish unique assets, observations, occurrences, executions,
scanner claims and validated claims. Actual totals come from matching count
queries or a complete aggregation, not lengths of capped display lists. Rows and
totals use consistent filters and a consistent snapshot. Unknown is not zero;
partial results say so. Counts never imply statistical certainty or completeness
of the unknown attack surface.

Graph edges, attack paths, context packets and summaries retain source links and
uncertainty. An LLM-inferred relationship is not silently a measured relation.
Generated summaries are disposable views and cannot serve as fresh corroboration
of their own source claims.

## 5. One methodology registry and coverage-driven scheduler

A testing unit has a stable internal methodology ID. WSTG/ATT&CK references are
optional mappings, not the scheduler's identity or proof of coverage.

### Check contract

Each check declares its version, purpose, subject type, prerequisites,
applicability, tool/action specification, required input/context, expected result
contract, retry/invalidation policy, resource/cost class and optional skill links.
Applicable does not mean authorized: admission remains a separate shared concern.
An unknown technology is not grounds to skip all generic web checks.

Start with ordinary validated configuration and registered adapters. Do not
invent a large workflow language or general-purpose rules engine. Multi-step
checks declare visible dependent actions using the same primitives.

Tool catalog = how to invoke a tool. Check registry = when and why to use it and
what its result means. Skills = investigative guidance. Each has one authoritative
home; no duplicate executable procedures embedded across several YAML files.

### Scheduling and durable work identity

The scheduler asks: "Which applicable check remains unfinished for this subject
and relevant context?" Work identity includes engagement, subject/request,
check version, relevant inputs and context version. Identical concurrent proposals
reuse or attach to the same work item unless an explicit rerun is requested.

Use transparent ordering: prerequisites/admission, explicit operator direction,
investigation urgency, breadth fairness and resource availability. Claimed impact
may prioritize a lead; it cannot change its truth status. Avoid several competing
weighted scores. Reserve progress for uncovered assets so endless depth on one
lead does not starve breadth.

Track execution state separately from test outcome. A process finishing is not
proof a check completed meaningfully. Outcomes distinguish match/no-match,
inconclusive, failure, interruption, not applicable and blocked prerequisites.

Persist successes, empty results, failures and retries through the same ledger.
Reopen work only on relevant changes, policy-defined retry/freshness or operator
request; an unrelated new observation must not reset every retry budget.
Freshness policy uses an explicit evaluation time; historical verdicts do not
silently change with wall-clock time.

Coverage is a versioned view of configured applicable checks on discovered
subjects: completed, pending, failed, blocked, excluded and unknown applicability.
"No match" means this check found no match, not "asset secure." Completion means
the configured run has no remaining runnable work within its bounds, with gaps
explained. It never claims all assets or vulnerabilities were discovered.

## 6. Automatic pentesting methodology and depth

Implement this incrementally through the same registry; tool names below are
examples from the existing catalog, not a mandate to run every overlapping tool.

| Evidence/input available | Automatic procedure | Example tools / output |
|---|---|---|
| Authorized domain | Passive names, certificates, DNS, registration, related-asset leads | subfinder, amass, crt.sh, dnsx, WHOIS; provenance-bearing leads |
| Names and DNS answers | Resolution, wildcard comparisons, dangling CNAME assessment, HTTP probing | dnsx, httpx, takeover checks; responders and DNS relationships |
| Approved network subjects | Port discovery, service enumeration, TLS inspection | naabu, nmap, tlsx/sslyze; scoped port/service observations |
| HTTP responders | Baselines, redirects, fingerprints, active crawl, historical URLs, JS/content discovery | katana, gau/wayback, js_recon, ffuf/feroxbuster |
| Web surface, including unknown technology | Generic baseline vulnerability checks and applicable specialist checks | nuclei, ZAP, nikto, WPScan, GraphQL checks |
| Service/version assertions | Research candidate advisories/exploits and record applicability uncertainty | searchsploit and configured intelligence sources; candidates, not confirmed CVEs |
| Requests and input locations | Parameter discovery and relevant injection testing preserving request context | arjun, SQLmap, Dalfox, applicable templates/checks |
| Authorized sessions and expected permissions | Authentication/session checks and role/object access comparisons | browser, proxy/replay, ZAP, configured access matrices |
| A promising claim | Check-specific validation with controls, or an investigation task | validators plus relevant LLM skill |
| New/changed relevant evidence | Reopen affected discovery/checks and expand applicable coverage | same scheduler; no second expansion loop |

Nuclei and SQLmap are part of the automatic methodology. SQLmap should receive
actual suitable requests/inputs, not be blindly launched once per hostname.
Combine generic baseline checks with technology-specific checks. Archive URLs
are leads until current behavior is measured.

Scope, action intensity and resource budgets remain explicit. Related/sister
domains, cloud/provider infrastructure and candidate origin IPs are not implicitly
authorized by discovery. Full-port escalation and intrusive actions require the
configured operator authorization; tool catalog category alone is not a risk
decision. Internal/AD, cloud/IaC and artifact/binary work become optional check
packs triggered by supplied access or artifacts, not always-run domain steps.

### Shared request/session collection — new core capability

Normalize reusable requests from crawlers, browser flows, proxy captures and
operators: method, URL, input locations, headers/body references, content type,
authentication context, discovery source and replay prerequisites. Preserve raw
requests. Retain application flows and token-refresh requirements where necessary.

All checks and the LLM use this collection rather than inventing incompatible
request models. Keep credentials out of ordinary logs/context, use secret
references, and record expired or invalid sessions explicitly. Login expiry must
not look like a clean scan or a successful authorization comparison.

Known role/resource/operation expectations support deterministic authorization
tests. Without those expectations, comparisons are investigation signals, not
proof of a business-policy violation. Missing credentials become a coverage gap.

### Baselines and controls — new shared capability

Provide reusable baseline requests, nonexistent-path comparisons, wildcard DNS
comparisons and repeated-response controls where a check needs them. Preserve
raw responses and record any normalization/masking. Controls must match the
relevant method, route, session and timing context.

Do not turn similarity into another universal truth score. A baseline helps a
particular validator distinguish signal from normal behavior; it must not erase
novel endpoints or globally suppress differences. Bound requests and concurrency
per application; avoid running redundant discovery tools without a purpose.

## 7. LLM investigation and operator extensibility

The LLM can investigate while methodology continues, propose bespoke actions,
request additional checks, explain evidence, and steer priorities. It does not
have to select every routine tool and does not merely approve a fixed pipeline.
Switching to operator-led or LLM-led work changes policy, not execution machinery.

Provide compact investigation packets: the question, subject/context, relevant
raw evidence links, observed versus asserted properties, prior attempts,
contradictions, coverage gaps and ranked relevant skills. All skills remain
discoverable; inject only relevant material within budget. Guidance-only skills
and zero-to-many check references are valid.

Trigger investigation on useful material changes, not repeatedly on an unchanged
lead. Track in-flight investigation and its evidence version in the same work
ledger. A failed/unavailable model does not stop independent deterministic work.
Target content is untrusted data, never authority to change instructions,
methodology, confirmation policy or engagement scope.

Operators can add a configured composition of existing checks/tools without
editing the core. A genuinely new technique can supply a script/adapter with a
declared result contract and positive/negative fixtures. Such extensions use the
same scheduler, provenance, execution and reporting contracts. They do not gain
validation authority merely by printing a marker or using a shipped tool name.

Validate configuration and declared cross-references on load and in CI. Apply
reloads atomically, retain last-known-good configuration, and pin in-flight work
to its configuration version. New versions affect new/re-evaluated work explicitly.
Keep shipped, operator-authored and LLM-proposed origins distinct. Learned skills
remain reviewable proposals; do not auto-rewrite executable methodology from one
successful engagement.

## 8. Observed defects motivating the design

These are focused review findings, not a claim of exhaustive audit. Reconfirm
against the implementation revision before changing code.

| Evidence in current source | Required architectural correction |
|---|---|
| `parsers/recon_network.py:parse_httpx` treats the last nonnumeric bracket as technology. Local fixtures produced technologies `Welcome` and `Not Implemented`. | Structured-field adapter; retain response facts without inferred title semantics. |
| `schemas/observation.py:observation_signature` lowercases target/details. Local fixtures gave `/Admin` and `/admin` the same signature. | Entity-aware identity and versioned migration. |
| `parsers/deterministic_confirm.py` assigns medium severity to reflection/difference. | Primitive measurement without invented impact. |
| `services/confidence.py` promotes using evidence-kind names and distinct tool count. | Bound claim validation and attributed assessment, not source counting. |
| `services/report_generator.py` computes totals from capped fetched lists. | Snapshot-consistent aggregation with explicit partial-view semantics. |

Paths above are relative to `backend/src/osprey/`. Other Plan 20 findings, such as
retry persistence asymmetry and competing execution responsibilities, are
implementation-audit targets; do not assume every older line reference remains
current.

## 9. Implementation sequence and deletion gates

### Milestone 0 — Contracts and controlled benchmark

- Inventory execution entry points, state writers, schedulers, retries and readers.
- Identify the components to reuse and one owner for each responsibility.
- Establish vulnerable and non-vulnerable fixtures before changing classifications.
- Specify minimal action/check/result/request contracts and identity migration.
- Reproduce the defects above and record baseline behavior and coverage.

Exit: tests fail for known defects and distinguish correct positive results from
correct non-findings. No production behavior has been reclassified silently.

### Milestone 1 — Honest evidence, identity and reporting

- Replace ambiguous extraction on the first selected tool path with a structured
  adapter; implement a bounded validator and provenance-preserving projections.
- Fix count aggregation and request/observation identity contracts.
- Remove primitive invented severity and count/label-based confirmation on the
  migrated path; migrate old records explicitly.
- Validate engagement ownership of every referenced evidence/subject ID, not only
  the request's top-level engagement field.

Exit: controlled positive/negative results, traces, totals and migration are correct
end-to-end. Extend adapter migration using the same pattern, not ad hoc filters.

### Milestone 2 — One runtime and durable work ownership

- Extract the shared headless runtime and action lifecycle.
- Route CLI, typed tools, managed workers and MCP actions through it.
- Unify attempt/retry bookkeeping and implement ownership, interruption recovery,
  attachment and event replay. Bound caches; caches are not correctness authorities.
- Migrate a representative deterministic check and LLM investigation into it.
- Retire replaced root loops before claiming unification complete.

Exit: two clients observe the same run; disconnect/restart/concurrent proposals
do not cross engagements, silently duplicate work or lose completed attempts.

### Milestone 3 — Useful automatic methodology, not just recon

- Consolidate existing procedures into the check registry and coverage scheduler.
- Deliver domain discovery -> service/web enumeration -> baseline -> applicable
  vulnerability check -> validation/candidate -> honest report without an LLM.
- Add request/session sharing, active crawling, generic baseline checks and
  evidence-triggered specialized checks. Expand to injection/authenticated slices.
- Integrate LLM investigation of a material lead while routine work continues.

Exit: the no-LLM path reaches vulnerability assessment; the LLM path adds useful
investigation without another queue/loop or repeated unchanged leads.

### Milestone 4 — Operator extension and interface completion

- Deliver a documented add-a-check example, schema validation, fixture workflow,
  atomic reload and check/skill provenance.
- Connect dashboard controls and views to the already-proven runtime.
- Demonstrate config-only composition and one genuinely new adapter using the
  same lifecycle. Broaden optional check packs based on measured gaps.

Exit: CLI and dashboard show matching state/counts; custom work needs no separate
orchestrator and cannot self-award evidence authority.

### Migration discipline throughout

- Use additive storage changes and preserve evidence during migration.
- Shadow-compare new parsing/projections against saved fixtures, never duplicate
  active target scans just to run both orchestration implementations.
- Switch ownership at a defined boundary; never let old and new root loops drive
  the same run concurrently. Rollback stops the new owner before reattachment.
- Temporary compatibility adapters translate to the new core; they contain no
  independent scheduling, retry or finding logic and have an explicit removal gate.
- Update AGENTS.md, phase briefs, skills, API descriptions and historical-plan
  pointers together. Audit contradictory guarantees and stale promotion advice.
- Remove superseded code/config/readers after callers migrate and tests pass.
  Do not declare completion while both old and new authoritative paths remain.

## 10. Release acceptance tests

1. **Evidence precision:** 200 titles, 401/403/501 responses, SPA shells,
   wildcard DNS and reflected tokens preserve their narrow facts without invented
   technology, exploitability or severity. Real positive examples remain visible.
2. **Claim binding:** genuine but unrelated excerpts cannot validate a different
   predicate, target, input or session; arbitrary script markers cannot confirm.
3. **Independent impact:** a validated low-level behavior plus a critical authored
   title never appears as a confirmed critical vulnerability without impact support.
4. **Identity:** case-sensitive paths remain distinct; appropriate hostname
   normalization works; vhosts, meaningful methods/inputs and sessions do not merge.
5. **Numbers:** datasets above display caps have exact totals or explicit partial
   labels; duplicates/reruns do not inflate unique counts; all interfaces agree.
6. **Isolation:** concurrent engagements, cross-engagement evidence IDs and
   ambiguous unbound requests cannot cross-write or cross-read scoped evidence.
7. **Durability:** empty results, failures, cancellations and exhausted retries
   survive restart; relevant changes reopen work, unrelated changes do not.
8. **Ownership:** duplicate submissions and concurrent clients produce one claimed
   work item; crash uncertainty is explicit; no unsafe automatic rerun assumption.
9. **Replay:** evidence order and repeat ingestion do not change derived verdicts;
   relevant recorded context/version changes can. Contradictions remain visible.
10. **Sessions/controls:** expired login, unstable pages and invalid controls make
    checks inconclusive, not falsely clean or confirmed. Valid detections still pass.
11. **Methodology:** a no-LLM lab run reaches vulnerability assessment, records
    negative results and produces candidates/validated results plus coverage gaps.
12. **LLM usefulness:** a material lead gets relevant evidence/skills and visible
    actions; unchanged leads are not endlessly reanalyzed; baseline work continues.
13. **Extensibility:** valid operator checks execute through the same lifecycle;
    invalid reloads preserve last-known-good state; active work keeps its version.
14. **Historical integrity:** legacy grades, suppressions and identity migrations
    preserve provenance without fabricating evidence or silently deleting records.
15. **Performance:** measure request volume, duplicate work, queue fairness,
    report latency, memory growth and LLM tokens on fixed fixtures. Set explicit
    budgets from the baseline rather than inventing improvement percentages.

Run controlled end-to-end slices first; a live authorized target is a later
operational check, not the sole correctness oracle. Completion requires published
test results and a reviewed list of remaining gaps, not a checklist of files edited.

## 11. Deliberate non-goals

- No second autonomous harness hidden behind an expansion tool.
- No universal regex/LLM judge for arbitrary semantic truth.
- No new confidence-weight framework, probability score or promotion ladder.
- No requirement to run every tool against every asset.
- No mandatory embeddings/vector database or distributed microservices rewrite.
- No full multi-tenant SaaS/RBAC project in this refactor; retain correct local
  engagement isolation and do not expose an unprotected dashboard remotely.
- No broad shell/session-management or RoE redesign; preserve existing controls
  and route actions consistently while concentrating on harness correctness/depth.
- No claim of complete pentesting, zero false positives, or comparative superiority
  until representative benchmarks support a precisely defined claim.

## 12. Primary references informing the design

- [HTTPX structured output and request/response capture](https://docs.projectdiscovery.io/opensource/httpx/usage)
  — use explicit fields rather than guessing from display text.
- [Nuclei workflows](https://docs.projectdiscovery.io/templates/workflows/overview)
  — reuse conditional/template mechanisms within the shared methodology.
- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
  — authentication-aware automation and job-result tests.
- [OWASP authorization testing automation](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html)
  — repeatable role/service/data expectations, not solely LLM judgment.

These are design references, not proof that an Osprey integration already works.

## Final definition

**One persistent pentesting workbench: methodology advances repeatable coverage;
the LLM investigates creatively; both use the same execution, evidence and state.
The platform records what happened and what each check established without
manufacturing stronger claims, inflated counts or hidden completion.**
