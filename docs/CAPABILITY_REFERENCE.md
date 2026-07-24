# AI Pentest Platform — Elite Operator Guide

Implementation-level reference for the capabilities added in Phases 1–7. It
explains not only what each function is for, but how inputs are normalized, how
calculations are performed, what is written to Postgres or process memory, what
queries actually search, where flexibility comes from, and which limitations
still exist.

> **Motto:** We do not hardcode the engagement. We give the LLM a lab, a shared
> notebook, searchable memory, and a proof referee so it can become an elite
> operator.

Defensive, authorized testing only.

---

## 1. Architecture

The platform now has three complementary roles:

### Lab

- Registered recon and network tools
- Allowlisted Kali shell
- Custom Python, Bash, and shell scripts
- Background jobs and bounded fanout
- Artifact paths and sliced output retrieval, with current capture limits
- Optional dependency installation

The LLM may choose an existing capability or invent an experiment when the
catalog does not cover the question.

### Shared notebook

- Structured findings
- Engagement asset graph
- LLM-authored relation names
- Operator asset tags and priority boosts
- Durable hypotheses
- Evidence-parent links (`derived_from`)
- Searchable attempt and finding memory

Memory is writable and searchable, so important cognition can survive beyond
the current chat context.

### Referee

- Engagement-bound storage and execution context
- Shell allowlists, scan-budget checks, and execution feature gates
- Scan-budget limits
- Evidence-grade severity clamps
- SPA false-API protection
- COMPLETE versus PARTIAL report gate

The referee is intended to control safety and proof integrity without selecting
the next tool. Current runtime boundaries are documented precisely in
[Section 22](#22-flexibility-hard-boundaries-and-current-policy-reality);
registered-tool governance is currently more permissive than this architectural
goal.

---

## 2. Thin prompt, fat memory

### The platform owns

- Scope and governance
- Evidence-grade severity limits
- Bootstrap parsing rules
- Configurable correlation thresholds
- Concurrency and scan-budget bounds
- Report-integrity checks

### The LLM owns

- Which uncertainty matters next
- Which tool, job, fanout, shell, or script to use
- Relation names and business meaning
- Hypotheses and confirmation strategy
- When to stop expanding
- The final evidence-grounded narrative

---

## 3. Phase summary

| Phase | Quality added       | Main function                                                      |
| ----- | ------------------- | ------------------------------------------------------------------ |
| 1     | Writable cognition  | Custom graph links, asset tags, durable hypotheses, script markers |
| 2     | Quiet guidance      | Open gaps and signals instead of imperative tool orders            |
| 3     | Richer perception   | 19 ingest patterns, correlation hypotheses, stdout index           |
| 4     | Parallel speed      | Background jobs, batch gaps, configurable concurrency              |
| 5     | Proof and reporting | Evidence chains, finalize referee, report outline                  |
| 6     | Hardening           | YAML source of truth, smoke suite, soft dry-run instincts          |
| 7     | Searchable recall   | Memory search, evidence traversal, attempt history                 |

---

## 4. Tool reference

### Orientation and memory

#### `platform_context`

Returns a compact engagement briefing:

- Active target and run
- Job-slot usage
- Open evidence gaps
- New memory delta
- Top crown jewels
- Recent artifact paths
- Inferred focus
- Finalize readiness

Open gaps describe unanswered questions. They are not commands.

#### `platform_memory_search`

Searches findings, graph nodes, and matching attempt history without dumping the
entire engagement.

```text
platform_memory_search(query="portal")
platform_memory_search(query="/api/")
platform_memory_search(query="Set-Cookie")
platform_memory_search(query="amass")
```

The search result is a flashlight. The LLM decides what the hits mean.

#### `platform_attempts`

Shows which tools were attempted near an asset:

```text
platform_attempts(asset="api.example.com")
```

Attempt history is advisory. It never forbids:

- Re-running with different parameters
- Setting `force_refresh=true`
- Starting a background branch
- Trying another capability
- Writing a custom script

#### `platform_evidence_chain`

Walks `derived_from` parents and children for a stored finding:

```text
platform_evidence_chain(finding_id="a1b2c3d4e5f6")
```

Use a finding ID returned by `platform_graph_link`,
`platform_record_finding`, or memory search—not a graph node ID or title.

---

### Writable cognition

#### `platform_graph_link`

Allows the LLM to name a relationship:

```text
platform_graph_link(
  source="host:erp.example.com",
  target="host:auth.example.com",
  relation="shares_auth_cookie",
  evidence="Same Set-Cookie Domain and issuer",
  evidence_grade="inferred",
  derived_from="findingA,findingB"
)
```

Relations are sanitized but not chosen from a fixed enum.

- `observed` evidence creates an asserted relation.
- `inferred` or `unverified` evidence becomes a `hypothesis_*` relation.
- `derived_from` records which findings support the interpretation.

Examples of LLM-authored relations:

- `calls_backend_api`
- `shares_auth_cookie`
- `likely_origin_of`
- `is_django_admin`
- `cors_exposes_to`
- `belongs_to_app_suite`

#### `platform_tag_asset`

Adds an operator role, reason, and score adjustment:

```text
platform_tag_asset(
  asset="api.example.com",
  role="data_backend",
  boost=35,
  reason="Observed authenticated user-data endpoint"
)
```

Tags improve crown-jewel prioritization without editing global scoring files.

#### `platform_think`

Persists an optional hypothesis into memory:

```text
platform_think(
  hypothesis="Portal and admin may share session validation",
  evidence="Same cookie domain and issuer",
  plan="Compare session behavior on both hosts"
)
```

Stored thinking is unverified. It is not proof and cannot support a high-severity
claim by itself.

#### `platform_record_finding`

Stores evidence that appeared in a tool or script but did not enter memory:

```text
platform_record_finding(
  title="Unauthenticated JSON user endpoint",
  evidence="HTTP/1.1 200 OK; Content-Type: application/json; {...}",
  finding_type="url",
  evidence_grade="observed",
  claim_severity="high",
  derived_from="parentFinding"
)
```

Severity is clamped by evidence grade.

---

### Adaptive execution

#### `platform_script`

Runs custom Python, Bash, or shell code inside Kali. This is the main invention
lane when product behavior is not represented in the catalog.

Scripts can print structured markers:

```text
FINDING|observed|high|url|Unauthenticated data endpoint|HTTP 200 application/json {...}
REL|inferred|host:portal.example|calls_backend_api|host:api.example|shared route prefix
HYPOTHESIS|portal and admin may share session validation
PATH /api/v1/users 401
```

These markers update findings and graph memory automatically.

#### `platform_shell`

Runs allowlisted binaries and simple pipelines. Governance still applies.

Use it for focused commands. Use `platform_script` when loops, complex logic,
or custom parsing are needed.

#### `platform_job_start`

Starts long-running work in the background and returns immediately:

```text
platform_job_start(
  kind="tool",
  tool="amass_scan",
  params_json={"domain": "example.com"},
  reason="Second independent discovery source"
)
```

The LLM should continue working on another relevant branch instead of waiting.
The platform only offers a soft parallel hint—it never starts jobs automatically.

#### `platform_job_poll` and `platform_job_result`

- Empty `platform_job_poll()` lists engagement jobs.
- Polling with a job ID retrieves its current status.
- `platform_job_result(job_id=...)` retrieves the completed result.

#### `platform_fanout_assets`

Runs a chosen capability across an LLM-selected shortlist. It is intended for
bounded batches, not automatic scanning of every discovered name.

#### `platform_install`

Installs approved dependencies for custom scripts when the standard library is
not enough.

---

### Artifacts and output

#### `platform_artifact`

Lists or reads full tool-output artifacts:

```text
platform_artifact()
platform_artifact(
  path="/tmp/pentest/<engagement>/tool.stdout.txt",
  offset=0,
  limit=80000
)
```

Tool cards show a compact preview. Artifacts preserve the larger output so the
LLM can retrieve only the slices it needs.

> **Known issue:** the current artifact reader can return an empty body because
> metadata and raw payload are framed through different buffering layers. The
> reliability plan requires separate metadata, seek-based slicing, uncapped
> capture, and traversal-safe canonical paths.

---

### Prioritization and reporting

#### `platform_crown_jewels`

Ranks high-value assets using evidence-derived reasons and operator tags.

#### `platform_finalize_check`

Returns either:

- `complete`
- `partial_only`

Hard claim-integrity blocks include:

- Unsupported CRITICAL/CVE claims
- HIGH claims without observed evidence
- SPA/HTML false-API claims

Inventory noise can be waived when strong observed impact exists. Claim
integrity cannot be silently waived.

#### `platform_report_outline`

Organizes stored memory into:

1. Observed findings
2. Inferred findings
3. Hypotheses and open gaps
4. Crown jewels and operator tags
5. Finalize status

The tool structures evidence; the LLM writes the report prose.

---

## 5. Automatic perception

`config/ingest_rules.yaml` contains bootstrap patterns for:

- HTTP status and titles
- HTTPX-style output
- Server and framework headers
- CORS wildcard headers
- Open ports
- Auth challenges
- Cookies
- Redirects
- TLS names and issuers
- Version banners
- Nmap service versions
- JSON content types and API-shaped bodies
- Console and application paths
- Subdomains
- Conservative JS/API route hints

The patterns help the LLM see more automatically. They do not determine which
tool must run next.

### Automatic correlation

`config/correlation_rules.yaml` currently proposes hypotheses such as:

- `likely_same_app`
- `shares_auth`
- `app_depth_candidate`

These are hypotheses, not observed impact.

> **Known limitation:** automatic correlations need stronger provenance. Future
> candidates should include contributing finding IDs, quoted evidence, positive
> and negative features, confidence rationale, rule version, and a stable
> fingerprint. The LLM should accept, reject, rename, or deepen candidates.

---

## 6. Evidence-grade law

| Grade      | Meaning                                             | Maximum valid claim                  |
| ---------- | --------------------------------------------------- | ------------------------------------ |
| Observed   | Direct response, banner, body, or verified behavior | HIGH/CRITICAL with substantive proof |
| Inferred   | Strong signal without direct impact confirmation    | MEDIUM                               |
| Unverified | Noise, hypothesis, raw output, or incomplete parse  | INFO                                 |

Examples:

- Observed: HTTP body, authentication response, service banner
- Inferred: DNS, certificate names, shared cookie domain
- Unverified: port flood, product title, operator hypothesis

### SPA false-API law

HTML returned from `/api`, `/swagger`, `/graphql`, or `/rest` does not prove a
working API. JSON content type and substantive body evidence are required before
claiming API impact.

> **Known limitation:** current SPA classification operates over aggregated
> stdout/stderr and can demote unrelated JSON if HTML appears elsewhere. It
> should become response-scoped and require catch-all corroboration.

---

## 7. Configuration map

| File                         | Controls                      | Design rule                                  |
| ---------------------------- | ----------------------------- | -------------------------------------------- |
| `ingest_rules.yaml`        | Stdout-to-finding patterns    | Bootstrap perception only                    |
| `correlation_rules.yaml`   | Hypothesis links and tags     | Never manufacture observed impact            |
| `parallelism.yaml`         | Job cap and soft hints        | Never auto-start                             |
| `finalize_rules.yaml`      | Proof thresholds              | Hard claim integrity, soft workflow guidance |
| `thinking_model.yaml`      | SIGNAL → CONFIRM → GRADE    | No per-vendor cognition packs                |
| `tech_dispatch.yaml`       | Technology signals            | Advisory signals, not orders                 |
| `escalation_matrix.yaml`   | Internal recovery             | Do not dump chains into normal MCP output    |
| `recon_network_tools.yaml` | Tool definitions              | Capability catalog, not engagement sequence  |
| `playbooks.yaml`           | Optional sequences            | LLM may alter, skip, or ignore               |
| `workflows.yaml`           | Optional structured workflows | Disabled by default for OpenCode mode        |

YAML is intended to be the source of truth.

---

## 8. Adaptive operator loop

This is an adaptive loop, not mandatory stages.

### 1. Orient

Bind authorized scope and call `platform_context` when orientation is useful.

### 2. Form a question

Choose one uncertainty that could materially change the engagement. Persist it
with `platform_think` only when durability helps.

### 3. Probe

Choose the best available mechanism:

- Typed tool
- `platform_exec`
- Background job
- Fanout
- Shell
- Custom script

### 4. Interpret

Read the result and decide what it means. Do not trust names, titles, or generic
correlations as impact.

### 5. Write back

- Record missing evidence
- Create meaningful relations
- Tag important assets
- Attach evidence parents

### 6. Reorient

Search memory, inspect attempts, or call context again. Choose another question
only if it contributes to the user’s goal.

### 7. Close honestly

Run:

```text
platform_findings()
platform_finalize_check()
platform_report_outline()
```

If finalize is blocked, deepen the relevant claim or publish a PARTIAL result.

---

## 9. What not to do

### Avoid narrow automation

- Do not treat hints as required tools.
- Do not add a vendor-specific stage for every fingerprint.
- Do not run every capability only to claim coverage.
- Do not auto-start jobs or fanout.
- Do not make static tool scores the “AI decision engine.”

### Avoid unsupported claims

- Do not infer an API from HTML 200.
- Do not claim a CVE from a product name or template title.
- Do not promote hypothesis edges to observed attack paths.
- Do not publish COMPLETE when finalize returns `partial_only`.

---

## 10. Troubleshooting

### New MCP tool returns HTTP 404

The MCP wrapper may be newer than the running backend route table:

```powershell
docker compose restart backend
```

Then reload OpenCode MCP.

Verify routes:

```powershell
$paths = (Invoke-RestMethod http://localhost:9000/openapi.json).paths.PSObject.Properties.Name
$paths | Where-Object { $_ -match "report-outline|memory-search|evidence-chain|attempts" }
```

### Evidence-chain ID not found

Use a stored finding ID. Find it through graph-link output, record-finding
output, or memory search.

### Memory search has no results

Try a distinctive hostname fragment, path, header, tool name, or tag. If the
evidence exists only in raw stdout, retrieve the artifact and record the
substantive fact.

### Attempt history shows an earlier run

History is not a ban. Change parameters, force refresh, branch into a job, use a
different capability, or invent another experiment.

### Finalize remains PARTIAL

Read `blocked_by` and the claim-specific checks. Verify, downgrade, or remove
unsupported claims. Partial reporting is valid and preferable to fabricated
completeness.

---

## 11. Verified reliability gaps and next work

Real OpenCode use identified improvements that should preserve flexibility:

1. Fix artifact framing and true large-file pagination.
2. Canonicalize Nmap `ports`, `flags`, and `additional_args`; never silently
   replace an explicit selector with `-F`.
3. Add durable append-only executions and jobs.
4. Add real job cancellation, timeout cleanup, heartbeats, and partial output.
5. Add structured shell stderr/output controls instead of enabling unsafe raw
   redirects.
6. Persist full attempt parameters, command identity, cache key, and artifacts.
7. Replace global context snapshots with cursor-based deltas.
8. Make evidence traversal recursive in both directions.
9. Emit provenance-rich correlation candidates for LLM acceptance or rejection.
10. Make SPA/API classification response-scoped.
11. Add layered, typed engagement preferences without exposing safety controls.
12. Persist and audit finalize override decisions.
13. Add backend/MCP version and capability handshakes.

The consolidated repository-backed implementation plan is:

`docs/ELITE_RELIABILITY_IMPLEMENTATION_PLAN.md`

---

## 12. Core data model and persistence

The platform uses ordinary relational storage rather than a dedicated graph
database. Four concepts matter:

1. **Engagement** — isolation boundary for one authorized target.
2. **Run** — audit stamp for one execution session.
3. **Finding** — evidence, inference, hypothesis, or operator annotation.
4. **Asset graph** — nodes and directed relations derived from findings or
   explicitly authored by the LLM.

### 12.1 Finding fields

Every finding has:

- `id`: random 12-character lowercase hexadecimal value.
- `engagement_id`: mandatory persistence boundary.
- `run_id`: run that created the finding.
- `phase`: optional compatibility/audit label.
- `finding_type`: `subdomain`, `host`, `url`, `port`, `service`,
  `technology`, or `observation`.
- `title`, `description`, and `evidence`.
- `confidence`: `confirmed`, `likely`, or `hypothesis`.
- `evidence_grade`: `observed`, `inferred`, or `unverified`.
- `claim_severity`: `none`, `info`, `low`, `medium`, `high`, or `critical`.
- `source_tool` and `target`.
- `metadata`: small structured fields used by graph, relation, and recall code.
- `tags`: free-form labels plus one normalized `grade:*` tag.
- `extra`: arbitrary nested JSON.
- `raw_data`: unstructured response or output excerpt.
- `notes`: operator or parser notes.
- `created_at`.

The SQL row does not have dedicated evidence-grade and severity columns.
Pydantic mirrors both values into:

```text
extra.evidence_grade
extra.claim_severity
```

When the row is read, model validation hydrates them from `extra`. It also
removes stale `grade:*` tags and appends exactly one current grade tag.

### 12.2 Finding write transaction

`FindingsStore.add_many()` performs this sequence:

```text
input findings
  → rerun Pydantic normalization
  → clamp severity to evidence grade
  → apply batch-local port-flood demotion
  → reject any row without engagement_id
  → db.merge each row by finding ID
  → increment engagement findings_count
  → update engagement timestamp
  → commit
```

Failure rolls the transaction back. Queries require an engagement ID, return
the newest `N` rows in chronological order, and cap a single request at 10,000
findings.

Equivalent content is not deduplicated. Re-running parsers or correlations can
create multiple random-ID findings describing the same fact.

### 12.3 Persistence matrix

Durable in PostgreSQL:

- Engagements and runs
- Findings
- Graph nodes and edges
- Latest tool coverage per `(engagement, tool, asset)`

Stored in the Kali container filesystem:

- Script files
- Script stdout/stderr
- Fallback tool-output artifacts

Process-local and lost on backend restart:

- Background job records and results
- Context-delta snapshots
- Recent stdout index
- Execution cache
- In-memory audit events

This distinction is important: “fat memory” currently applies most strongly to
findings and graph data, not every operational object.

---

## 13. Evidence grading and severity calculation

### 13.1 Grade and confidence are different

Evidence grade answers:

> How directly did the platform observe this claim?

Confidence answers:

> How strongly does the parser or operator believe the interpretation?

An observation may therefore be `confidence=confirmed` but still
`evidence_grade=inferred` if it confirms only an indirect signal.

### 13.2 Default grade algorithm

When a parser does not provide a grade, `default_grade_for_type()` evaluates in
this order:

```text
if tags contain raw_output, unparsed, or honeypot_suspect:
    grade = unverified
else if tags contain sister_domain or source_tool == domain_hunter:
    grade = unverified
else if finding_type is URL or SERVICE:
    grade = observed
else if finding_type is TECHNOLOGY, PORT, SUBDOMAIN, or HOST:
    grade = inferred
else if finding_type is OBSERVATION and confidence == hypothesis:
    grade = unverified
else:
    grade = inferred
```

Why:

- A live URL or service parser normally has a response/banner.
- A port state, DNS name, or technology fingerprint is usually a signal rather
  than demonstrated impact.
- A hypothesis is deliberately prevented from becoming proof through confidence
  wording alone.

### 13.3 Severity is assigned, then clamped

The platform does **not** currently calculate CVSS, exploitability, likelihood,
business impact, or a numeric risk score.

A parser, YAML rule, script marker, or operator requests a severity. The model
then applies this ordinal ranking:

```text
none=0 < info=1 < low=2 < medium=3 < high=4 < critical=5
```

Grade ceilings:

```text
observed   → critical
inferred   → medium
unverified → info
```

Formula:

```text
final_severity =
    requested_severity
    if rank(requested_severity) <= rank(max_for_grade)
    else max_for_grade
```

Examples:

```text
observed + critical   → critical
observed + low        → low
inferred + critical   → medium
inferred + high       → medium
unverified + high     → info
unverified + critical → info
```

The clamp is a ceiling, not an upgrade. `observed + low` remains low.

Unknown values passed to the standalone clamp are conservative:

- Unknown grade → `unverified`
- Unknown severity → `none`

### 13.4 Port-flood demotion

For one submitted finding batch:

```text
if port_findings_for_host >= 40
and service_findings_for_host < 3:
    grade = unverified
    severity = info
    add tags honeypot_suspect and port_flood
```

This reduces the chance of treating SYN noise or a decoy as dozens of real
services. The finding note asks the operator to banner-verify two or three
services.

Limitation: store-time demotion sees only the current batch. Forty one-at-a-time
writes are not retrospectively changed, although finalize performs a separate
cumulative flood check.

### 13.5 What “observed” does and does not mean

`observed` means the caller or parser supplied direct-looking evidence. It does
not cryptographically bind the finding to an artifact. A script or manual call
can claim `observed`; finalize adds length/marker checks, but the LLM must still
inspect whether the evidence genuinely proves the title.

---

## 14. Finding creation and automatic ingest

One execution can produce findings through two independent paths.

### 14.1 Deterministic parser path

`summarize_execution()`:

1. Runs the parser registered for the selected tool.
2. Uses free-form parsing when:
   - execution came from shell or script,
   - the registered parser produced nothing, or
   - it produced only generic observations.
3. Creates an unverified raw-output fallback when forced and no structure was
   found.
4. Stores findings.
5. Projects supported finding types into the graph.
6. Parses `REL|...` markers separately into graph links.

Raw fallback findings retain up to 24,000 characters and use:

```text
confidence=hypothesis
evidence_grade=unverified
tags=[raw_output, unparsed, grade:unverified]
```

### 14.2 Universal YAML promotion path

`apply_ingest_rules()` also examines combined stdout and stderr:

```text
stdout + stderr
  → inspect first 8,000 characters for SPA markers
  → load ingest_rules.yaml
  → compile each regex case-insensitively
  → take up to 8 matches per rule
  → render title captures
  → apply grade/severity from YAML
  → apply SPA and weak-evidence demotions
  → clamp severity
  → persist up to 40 promoted findings
  → graph-project supported types
  → run cross-finding correlation
```

Rule-title duplicates are removed only within that one ingest invocation.
Registered parser findings and YAML findings may both describe the same output.

The current YAML has 19 rule entries covering HTTP/server fingerprints, CORS,
ports, SPA catch-all, JSON bodies, admin paths, subdomains, HTTP titles, httpx,
auth challenges, cookies, redirects, TLS identity/issuer, version banners,
Nmap services, JSON content type, and JavaScript route hints.

### 14.3 Free-form marker grammar

Explicit finding:

```text
FINDING|<grade>|<severity>|<type>|<title>|<evidence>
```

Example:

```text
FINDING|observed|high|url|Open admin API|HTTP 200 application/json {"users":[]}
```

Rules:

- Title is one line and cannot contain `|`.
- Evidence is one-line text.
- Grade and severity use the normal clamp.
- Observed markers become `confidence=confirmed`.
- Other grades become `confidence=likely`.

Hypothesis:

```text
HYPOTHESIS|<title>|<evidence>
```

The final pipe and evidence field are required by the parser, though evidence
may be empty. A hypothesis becomes an unverified observation; it does not create
a graph edge.

Relation:

```text
REL|<source>|<relation>|<target>|<evidence>
REL|<grade>|<source>|<relation>|<target>|<evidence>
```

Default grade is inferred. `REL|` uses the same relation sanitizer and graph
write path as `platform_graph_link`, but it currently cannot supply
`derived_from`.

Other recognized forms:

```text
PATH /api/users 401
ENDPOINT https://host/rest/info 200
ROUTE /account/settings
https://host/path 200 Title
host.example:443 open
host.example resolves to 192.0.2.10
```

Free-form parsing caps output at 200 findings and processes hypotheses before
explicit findings, paths, URLs, ports, and DNS lines. If the cap is reached,
later categories are omitted.

---

## 15. Engagement graph: exact write behavior

### 15.1 Node identity

Node IDs are deterministic inside one engagement:

```text
node_id = "<asset_type>:<lowercased-label>"
```

Examples:

```text
host:erp.example.com
ip:192.0.2.10
url:https://example.com/api
port:example.com:443
technology:django
```

The database key is:

```text
(engagement_id, node_id)
```

Therefore identical labels in two engagements remain isolated.

Only lowercasing is guaranteed. URL query ordering, trailing slashes, default
ports, percent encoding, Unicode/punycode, and IPv6 equivalent forms are not
canonicalized. Semantically identical assets can become separate nodes.

### 15.2 Node updates

When a node already exists, metadata uses a shallow merge:

```python
merged = {**old_metadata, **new_metadata}
```

New values replace old values for matching keys. The node’s `run_id` also
changes to the latest non-empty writing run, so it is a latest-write stamp, not
creation history.

### 15.3 Edge identity

Edges are directed and unique by:

```text
(engagement_id, source_id, target_id, relationship)
```

Self-edges are silently skipped. Repeating the same source, target, and relation
does not add another edge.

The edge table currently stores no:

- Evidence
- Grade or confidence
- Timestamp
- Run ID
- Metadata
- Foreign key to its supporting finding

Operator-link proof lives in a separate finding.

### 15.4 Automatic finding-to-graph projection

The graph projector performs:

```text
SUBDOMAIN
  → subdomain node
  → optional resolves_to IP
  → optional bidirectional co_hosts links

HOST
  → host node
  → optional resolves_to IP
  → optional bidirectional co_hosts links
  → if sister/affiliate: seed DOMAIN --affiliated_with--> host

URL
  → URL node
  → host node parsed from URL
  → URL --hosted_on--> host

PORT
  → port node
  → host node
  → host --has_port--> port

SERVICE
  → service node only

TECHNOLOGY
  → technology node only

OBSERVATION
  → no automatic node or edge
```

Current omissions:

- Service nodes are not linked to ports.
- Technology nodes are not linked to hosts or URLs.
- Normal subdomains are not linked to a parent domain.
- Findings are not graph nodes.
- There is no automatic finding-to-edge provenance relation.

### 15.5 Host/IP extraction limits

For host/subdomain findings, IP comes from `metadata.ip` or the first
IPv4-shaped substring in evidence. Octet ranges are not validated.

URL host extraction uses string splitting rather than a full URL parser. IPv6
literals, credentials, and unusual URL forms may be parsed incorrectly.

Port host selection prefers `finding.target`; a broad seed target can therefore
anchor a port incorrectly if parser metadata is weak.

---

## 16. `platform_graph_link` in detail

### 16.1 Asset parsing

Explicit prefixes:

```text
domain:
subdomain:
host:
ip:
url:
port:
service:
technology:
```

Without a known prefix:

```text
http:// or https:// → URL
IPv4-shaped text    → IP
/leading/path       → URL
everything else     → HOST
```

Bare host labels are lowercased. IPv6 is not inferred without an explicit type.

### 16.2 Relation normalization

Input:

```text
"Shares Auth-Cookie!"
```

Normalization:

1. Trim and lowercase.
2. Replace spaces and hyphens with `_`.
3. Remove characters outside `[a-z0-9_]`.
4. Collapse repeated underscores.
5. Trim underscores.
6. Truncate the final relation to 64 characters.

Then evidence grade controls assertion state:

```text
observed:
    shares_auth_cookie

inferred or unverified:
    hypothesis_shares_auth_cookie
```

Unknown grades become `inferred`. If the user already supplied
`hypothesis_`, the code removes and reapplies it once.

### 16.3 What one link call writes

```text
platform_graph_link(...)
  → parse source and target
  → sanitize relation
  → require non-empty evidence
  → upsert source node
  → upsert target node
  → add directed edge if unique
  → create an observation finding
  → attach optional derived_from IDs to finding metadata
  → return source ID, target ID, relation, finding ID
```

The relation finding includes:

```text
source_tool = operator_graph_link
metadata.source_id
metadata.target_id
metadata.relationship
metadata.operator_relation
metadata.edge_kind = asserted | hypothesis
metadata.derived_from = [...]
tags = operator_graph_link, asserted_link|hypothesis, rel:<name>
```

Observed relation:

```text
confidence=confirmed
edge_kind=asserted
```

Non-observed relation:

```text
confidence=hypothesis
edge_kind=hypothesis
```

All relation findings use `claim_severity=none`; a relationship is not itself a
vulnerability severity claim.

### 16.4 Flexibility

There is no fixed business-relation enum. The LLM can create:

```text
calls_backend_api
shares_auth_cookie
likely_origin_of
is_admin_console_for
cors_exposes_to
belongs_to_app_suite
depends_on_identity_provider
```

The platform controls syntax and evidence state, while the LLM supplies meaning.
This is the main “no hardcoded engagement” property of graph write-back.

### 16.5 Important limitations

- An observed relation may reuse structural names such as `hosted_on`; the
  comment about reserving these names is not enforced.
- Distinct long relation names can collide after truncation.
- Repeated calls deduplicate the edge but still create a new relation finding.
- Edge evidence can only be recovered by locating the separate finding.
- `REL|` script markers cannot attach `derived_from`.

---

## 17. Tags, crown-jewel ranking, and calculations

### 17.1 `platform_tag_asset`

The call requires:

- Asset
- Reason
- Optional role
- Optional boost

Role normalization:

```text
lowercase
hyphen → underscore
remove characters outside [a-z0-9_]
empty → operator_priority
```

Boost is clamped:

```text
-50 <= boost <= 100
```

One call writes twice:

1. Node metadata:

```text
operator_role
operator_boost
```

2. Inferred observation finding:

```text
source_tool=operator_tag_asset
confidence=likely
severity=none
metadata.asset
metadata.asset_type
metadata.operator_role
metadata.operator_boost
```

Later tags overwrite node metadata, while earlier tag findings remain.

### 17.2 Crown-jewel grouping

For each finding:

```text
asset = finding.target or finding.title
```

HTTP-like assets are reduced to hostname. Scoring is additive and currently
occurs once per finding, not once per unique fact.

### 17.3 Exact score contributions

For each finding:

```text
for each configured role regex matching asset or full finding blob:
    score += role_weight

for each technical regex matching the blob:
    CORS wildcard     +20
    SPA catch-all     -25
    auth challenge    +15
    vendor X-header   +12

if evidence_grade == observed:
    score += 8

if severity is high or critical:
    score += 12 when observed
    score += 3 otherwise
```

Current role weights from `thinking_model.yaml`:

```text
remote access       40
mail                38
device management   36
DevOps              35
admin/identity      32
voice               30
API                 28
business portal     24
```

For each graph node:

```text
matching role regex:
    score += max(5, floor(role_weight / 2))

operator_boost in node metadata:
    score += operator_boost
```

Finally, the latest operator-tag finding for each asset adds its boost.

Results:

```text
sort by score descending
tie-break by asset string
discard score <= 0
return up to requested limit
show at most 8 reasons per row
```

### 17.4 Current scoring defects and limits

The same operator boost is currently added:

1. From node metadata.
2. Again from the operator-tag finding.

Therefore `boost=40` commonly contributes `80`. This is a known defect, not the
intended formula.

Repeated findings also repeat role, technical, observed, and severity points.
Current ranking has no:

- Graph centrality
- Unique-tool weighting
- Edge-count weighting
- Recency decay
- Exploitability calculation
- Business-impact model
- Semantic deduplication

Treat crown-jewel scores as prioritization hints, not objective risk values.

---

## 18. Correlation and evidence chains

### 18.1 Current automatic correlations

Correlation runs after universal YAML ingest and reads up to 2,000 engagement
findings.

#### Same IP plus similar title

For two HTTP titles, tokens are lowercase alphanumeric words with length at
least three.

```text
overlap =
    count(tokensA ∩ tokensB)
    / max(count(tokensA), count(tokensB))
```

If:

```text
same resolved IP
AND overlap >= 0.5
AND title length >= 4
```

the correlator adds:

```text
hypothesis_likely_same_app
```

Maximum: 12 links per correlation invocation.

#### Shared cookie domain

If two hosts have findings containing the same:

```text
Set-Cookie ... Domain=<domain>
```

the correlator adds:

```text
hypothesis_shares_auth
```

Maximum: 8 links per invocation.

This is only a signal. A shared cookie domain does not prove equivalent session
validation.

#### URL fanout

If a host has at least five URL or JavaScript-route findings, it receives:

```text
role=app_depth_candidate
boost=12
```

Maximum: 6 tags per invocation.

### 18.2 Correlation flexibility

Thresholds, relation names, grades, boosts, and per-run caps live in
`correlation_rules.yaml`. The LLM can:

- Ignore a weak candidate.
- Query both assets.
- Confirm it with a new observed relation.
- Rename the relation to capture business meaning.
- Add `derived_from` parents manually.

### 18.3 Correlation limitations

- Rule types themselves are implemented in Python; YAML selects among three
  current algorithms.
- Generated links contain descriptive evidence but no source finding IDs.
- Re-running correlation can create duplicate relation findings.
- Correlation output is always soft/hypothesis-level.
- Cookie and title extraction are regex/string based.

### 18.4 `derived_from`

Accepted inputs include comma/space/semicolon-separated strings, lists, or
tuples. Normalization:

```text
lowercase
deduplicate in original order
retain at most 20 parent IDs
```

Allowed IDs are either:

- 8–32 hexadecimal characters, or
- 6–40 alphanumeric/underscore/hyphen characters.

Parent existence and engagement ownership are not validated during the write.

### 18.5 Evidence-chain query

`platform_evidence_chain(finding_id, depth)`:

1. Loads up to 5,000 engagement findings.
2. Looks for exact ID.
3. If missing, allows prefix matching in either direction.
4. Traverses `derived_from` parents breadth-first.
5. Stops at depth 1–8.
6. Marks unresolved parents as missing.
7. Scans all loaded findings for direct children citing the root.
8. Returns at most 30 children.

Important:

- Parent traversal is recursive.
- Child traversal is only one level.
- Grade does not propagate through the chain.
- An observed parent does not automatically upgrade an inferred child.
- Chain links are finding metadata, not graph edges.
- Prefix matching may be ambiguous.

---

## 19. Graph query and memory query behavior

### 19.1 `platform_graph_query`

Inputs:

```text
asset_type: optional exact type filter
contains: optional case-insensitive substring
limit: clamped to 1..500
```

Algorithm:

```text
load up to 20,000 nodes of requested type
for each node:
    match contains against label
    if no label match:
        match against stringified metadata values
    retain until limit

load up to 10,000 edges
return edges where source OR target is a matched node
cap edges at 2 * limit
```

Each returned edge has:

```text
source
target
rel
hypothesis = rel starts with "hypothesis_"
```

What it can do:

- Find all host nodes containing `admin`.
- Find nodes with metadata values containing `cloudflare`.
- Show incident relations for those matched nodes.
- Distinguish hypothesis relations by prefix.

What it cannot yet do:

- Multi-hop traversal
- Shortest paths
- Relation filtering
- Regex or fuzzy search
- Ranking or pagination
- Graph-centrality analysis
- Return edge evidence or grade

Incident edges may reference an endpoint that is not included in the matched
node list.

### 19.2 `platform_memory_search`

The query is lowercased and matched as a literal substring.

Finding search covers:

```text
title
description
first 400 evidence characters
source_tool
target
tags
metadata.relationship
```

Order:

1. Search up to 5,000 findings.
2. If the result limit is not full, search up to 3,000 graph nodes.
3. Attach related tool-coverage rows.

Graph-node search covers label, ID, and asset type.

There is no token ranking, stemming, fuzzy matching, full-text index, or
pagination. Finding hits may consume the whole limit before graph nodes are
considered.

Good searches:

```text
platform_memory_search(query="Set-Cookie")
platform_memory_search(query="/api/v2/")
platform_memory_search(query="portal.example")
platform_memory_search(query="hypothesis_shares_auth")
platform_memory_search(query="nmap_service_scan")
```

### 19.3 `platform_attempts`

The current table key is:

```text
(engagement_id, tool_name, asset)
```

When the same tool runs again on the same normalized asset, the row is updated.
It is therefore **latest coverage state**, not complete append-only history.

Stored fields:

- Run ID
- Tool name
- Asset
- Success
- Finding count
- Notes
- Completion time

Not stored:

- Full parameters
- Final command
- Cache key
- Timeout
- Artifact paths
- Every previous attempt

Filtering is a simple substring over asset or tool name. The result is advisory;
it must never become a hard “already tried, skip forever” rule.

---

## 20. Context, open gaps, jobs, and artifacts

### 20.1 `platform_context` assembly

The adaptive context builds recon and network packets, merges them, and adds:

- Findings summary
- Graph summary and pivots
- Coverage gaps
- Attack-surface tree
- Network surface
- Inferred focus
- Finalize readiness
- Crown jewels
- Thinking cards
- Open loops
- Recent stdout index
- Background jobs
- Context delta

The MCP response intentionally displays compact slices rather than the full
objects.

### 20.2 Open-loop calculations

Open loops are generated in fixed order and truncated; they are not scored.

`ips_unscanned`:

```text
network surface has IPs with no port findings
```

`ports_no_service`:

```text
IPs have port findings but no service findings
```

`hosts_no_http`:

```text
named hosts >= 5
AND HTTP-backed hosts < max(3, floor(named_hosts / 3))
```

`app_depth`:

```text
HTTP findings exist
AND no recorded coverage tool begins with "script:"
```

`batch_probe_pending`:

```text
HTTP hosts >= parallelism.batch_probe_min_hosts
OR named hosts >= parallelism.batch_probe_min_subdomains
AND no job/fanout coverage is seen
```

`sisters`:

```text
hosts exist AND domain_hunter is absent from coverage
```

`second_enum`:

```text
subfinder is the only recognized enumeration source
AND host count < 80
```

Structured hints name capability classes, but normal text omits them. This lets
the LLM choose a catalog tool, job, fanout, script, graph write, or justified
skip.

Limitations:

- Host extraction uses simple title parsing.
- Any script use suppresses `app_depth`.
- Any job can suppress `batch_probe_pending`, even an unrelated one.
- Fixed ordering can hide later gaps when the result is truncated.

### 20.3 Context delta

The backend stores one process-local snapshot per engagement:

```text
nodes
findings
ports
urls
observed
timestamp
```

First call returns absolute counts using `+nodes`, `+findings`, and similar
keys. Later calls return:

```text
delta = current - previous
```

The snapshot is:

- Lost on backend restart.
- Shared by all callers of the engagement.
- Advanced by internal context construction as well as user calls.
- Not a durable cursor.

This explains why deltas can remain zero or appear inconsistent.

### 20.4 Background jobs

Job creation:

```text
validate engagement and kind-specific fields
  → read max_running_jobs from parallelism.yaml
  → count queued/running jobs for engagement
  → reject if cap reached
  → create job_<12 hex chars>
  → store _JobRecord in process memory
  → asyncio.create_task(_run)
  → dispatch through normal tool/shell/script service
```

Current default cap is four running jobs per engagement.

Soft background suggestion:

```text
suggest = tool in configured long_tools
          OR timeout >= suggest_job_timeout_seconds
```

Suggestion never starts a job.

Job states:

```text
queued → running → completed|failed
```

`cancelled` exists in the enum but has no working cancellation endpoint.

Current job limitations:

- No durability across backend restart.
- No heartbeat.
- No partial-output API.
- No cancellation.
- No orphan reconciliation.
- No explicit child-process cleanup on every timeout path.
- At most 200 records retained in memory.

### 20.5 Fanout is batching, not parallelism

Both fanout variants execute assets sequentially with `await` inside a loop.
They provide:

- Explicit shortlist handling
- Deduplication
- Tool restrictions
- Dry-run preview
- Confirmation before execution

They do not currently run assets concurrently.

### 20.6 Stdout index

The index stores at most 24 process-local entries per engagement:

```text
timestamp
tool
target
stdout path
stderr path
snippet
byte hint
success
```

Snippets longer than 400 characters are shortened to the beginning and end.
The index disappears on restart even if files still exist.

### 20.7 Artifact capture and pagination

`platform_artifact` permits:

- Basename under the engagement workdir.
- Full path under `/tmp/pentest/<engagement_id>/`.

It blocks cross-engagement paths and `..` traversal. Offset is non-negative and
limit is clamped to 1–500,000.

Intended result:

```text
total_bytes
offset
end
returned_bytes
content
truncated
next_offset
```

Current limitations:

1. Catalog/shell output is capped before fallback artifact writing
   (approximately 50 KB stdout and 10 KB stderr), so the fallback file may not
   contain the original full process output.
2. The reader calls `read_bytes()` on the whole file before slicing, which is
   not true large-file seek pagination.
3. Buffered metadata prints mixed with raw binary writes can reorder framing and
   produce empty or malformed content.
4. Files live under Kali `/tmp` and may disappear when the container is replaced.

Scripts are better because their stdout/stderr are redirected directly to files
before preview truncation.

---

## 21. Tool execution and extensibility

### 21.1 Catalog execution pipeline

`platform_exec` follows:

```text
MCP wrapper parses params dict/JSON
  → clamp timeout
  → resolve tool definition
  → resolve engagement/run
  → governance check
  → merge additional_args
  → fill missing primary target from engagement seed
  → normalize target/domain/host/url aliases
  → reject blocked metacharacters
  → validate required fields
  → apply scan-budget guard
  → compute cache key
  → return cache hit or build command
  → execute inside Kali
  → deterministic parser
  → free-form parser when relevant
  → universal YAML ingest
  → graph projection and correlation
  → update latest tool coverage
  → store/index artifact preview
  → update engagement counters
  → attach soft recovery/dispatch/parallel hints
  → cache successful non-empty response
  → format compact MCP result
```

### 21.2 Cache formula

The key is SHA-256 over stable JSON containing:

```text
engagement_id
tool_name
sorted normalized params
stripped additional_args
```

Current TTL is one hour and the cache holds up to 512 process-local entries.
Only successful, non-timeout, non-empty responses are cached.

`force_refresh=true` bypasses reuse.

### 21.3 `additional_args`

The LLM can supply parameters beyond common examples through `additional_args`,
`extra_args`, or `flags`. This is an important flexibility lane: YAML defines a
capability, not every valid command combination.

Catalog string values reject shell-control characters such as:

```text
; | & ` $ ( ) < >
```

Complex execution belongs in `platform_script`.

### 21.4 Nmap normalization

Current normalization:

- Replaces unprivileged `-sS` with `-sT`.
- Adds `-Pn` and `--unprivileged`.
- Removes an accidental leading `-p` from the `ports` field.
- Uses `-sT -Pn -F --unprivileged` when custom flags are empty.

Known defect: the custom Nmap command builder can ignore the explicit `ports`
field and select `-F`. The reliability plan must canonicalize port selection and
reject conflicts rather than silently changing operator intent.

### 21.5 Shell

`platform_shell`:

- Splits a simple pipeline.
- Parses each stage with `shlex`.
- Requires each executable to be in the runtime Python allowlist.
- Rebuilds stages safely with `shlex.join()`.
- Blocks redirects, substitutions, loops, `;`, `&&`, `||`, backgrounding, and
  newlines.
- Applies scan-budget checks.
- Parses and ingests output like other execution lanes.

This is deliberately restrictive. Complex branching, output control, or custom
logic should use script execution.

Current limitations:

- Runtime allowlist is hardcoded in Python and can drift from
  `kali_allowlist.json`.
- There is no shell `confirm_expensive` argument.
- Output is capped before fallback artifacts.

### 21.6 Script

`platform_script`:

- Supports Python/Python 3, Bash, and sh.
- Allows up to 200,000 bytes of code.
- Requires a safe relative filename.
- Optionally installs validated Python packages first.
- Writes the script under the engagement workdir.
- Executes the stored file without `shell=True`.
- Redirects stdout/stderr to files.
- Does not use execution cache.
- Ingests markers and generic output when `record_findings=true`.

Scripts keep the platform open-ended. A new product-specific experiment does not
require a new hardcoded stage or agent.

Current safety gap: script code does not pass through the catalog/shell
scan-budget checker, so governance must eventually enforce equivalent
engagement policy at the execution boundary.

### 21.7 Install

Pip installation:

- Feature-gated.
- Up to 15 validated PyPI specs.
- Rejects URLs, paths, spaces, and shell syntax.

Apt installation:

- Separately feature-gated.
- Up to 15 packages from a fixed allowlist.
- Can fail if the Kali user lacks privileges.

---

## 22. Flexibility, hard boundaries, and current policy reality

### 22.1 Flexible/advisory mechanisms

- Open gaps and focus signals
- Crown-jewel scores
- Attempt state
- Playbooks and skills
- Background-job suggestions
- Correlation candidates
- Arbitrary sanitized relation names
- Asset roles and bounded priority boosts
- Custom scripts and structured markers
- Extra catalog arguments
- YAML ingest/correlation/finalize thresholds
- Hypothesis-only path warnings
- Report outline structure

These should help the LLM think, not select the engagement strategy for it.

### 22.2 Hard technical boundaries currently enforced

- Finding writes require an engagement.
- Findings and graph are engagement-isolated.
- Severity cannot exceed its evidence-grade ceiling.
- Non-observed graph relations receive `hypothesis_`.
- Shell stages require allowlisted executables.
- Catalog and shell strings reject dangerous metacharacters.
- Wide/full scans are checked by scan-budget logic.
- Fanout requires explicit confirmation after dry run.
- Package names are validated and apt is allowlisted.
- SPA false-API claims can block COMPLETE.
- Persistence failures roll back their SQL transaction.

### 22.3 Boundaries that are not yet truly hard

The current governance engine approves every registered tool, including tools
marked `GATED`. Scope rules, rules of engagement, category blocks, and approval
checks are not actively enforced by `GovernanceEngine.check()`.

Consequences:

- `GATED` is currently descriptive.
- Stored rules of engagement are not fully enforced.
- Script code bypasses shell allowlists and scan-budget checks.
- `platform_finalize_check(override=true)` bypasses all report blockers.
- Finalize advises the LLM; it cannot stop someone from writing “FINAL.”
- Manual/script observed findings trust caller-provided evidence.

The platform therefore has useful execution controls and strong evidence
clamping, but it should not yet be described as a complete policy-enforcement
boundary.

---

## 23. Finalize and report calculations

### 23.1 Strong observed evidence

A finding is “strong observed” when:

```text
evidence_grade == observed
AND (
    length(raw_data + evidence + description) >= 80
    OR (
        a configured strong marker is present
        AND combined length >= 24
    )
)
```

Current markers:

```text
http/
banner
set-cookie
www-authenticate
openssh
server:
content-type: application/json
```

This is stronger than trusting a title, but still heuristic. A short,
header-looking string can satisfy it.

### 23.2 Finalize inputs

The check reads:

- Up to 5,000 findings
- Coverage gaps
- Up to 5,000 graph nodes
- Inferred engagement focus
- `finalize_rules.yaml`

### 23.3 Claim-integrity checks

`unverified_high_claims`:

```text
any high/critical finding whose grade is not observed
```

`weak_critical_claims`:

```text
critical finding without strong observed evidence
OR CVE-named high finding without strong observed evidence
```

`spa_false_api_claims`:

```text
SPA-tagged or API-path+HTML finding
with medium/high/critical severity
```

`hypothesis_only_attack_path`:

```text
only when finalize_rules.block_hypothesis_only_paths == true
AND hypothesis relation findings exist
AND strong observed high count is below configured minimum
```

Current YAML sets this last check to a soft warning.

### 23.4 Thin-memory checks

`evidence_too_thin`:

```text
URLs < 3
AND services < 3
AND observed findings < 5
```

`memory_thinner_than_narrative`:

```text
raw/unparsed observations >= 3
AND structured observed < 5
AND all structured findings < 8
```

`structured_observed_too_thin`:

```text
structured observed findings < 5
```

The check also considers coverage gaps, shallow inferred focus, missing app
depth, and cumulative port floods.

### 23.5 Infrastructure-noise waiver

Infrastructure/inventory blockers can be waived when:

```text
strong observed impact count >= 2
OR
there is at least one non-SPA/non-honeypot
high|critical finding with strong observed evidence
```

Waivable examples:

- Thin inventory
- Resolution gaps
- Port-flood noise
- Shallow surface
- Low structured count

Not waived:

- Unverified HIGH/CRITICAL
- Weak CRITICAL/CVE
- SPA false API
- Hard-configured hypothesis-only path

### 23.6 Final result

```text
blocked_by is empty:
    can_finalize = true
    report_mode = complete

blocked_by is not empty:
    can_finalize = false
    report_mode = partial_only

user_override == true:
    can_finalize = true
    report_mode = complete
    blocked_by remains visible
```

Current override is not durably audited or persisted as a decision record.

### 23.7 Report outline classification

Each finding is assigned to one section:

Hypotheses:

```text
grade == unverified
OR hypothesis tag/confidence/title
OR operator_think
OR hypothesis relation
```

Observed:

```text
grade == observed and not already hypothesis
```

Inferred:

```text
everything else
```

Each line includes:

```text
[grade|severity] title
(id=<finding_id> via <source_tool>)
← up to four derived_from IDs
```

The outline also includes crown jewels, open gaps, and finalize mode. It returns
only the last configured number per evidence section—currently 25—and does not
sort by severity.

The outline organizes memory. It does not write the narrative or guarantee that
the LLM quotes the underlying evidence correctly.

---

## 24. Worked example: evidence to graph to report

Suppose a script prints:

```text
FINDING|observed|high|url|Unauthenticated user endpoint|HTTP/1.1 200 OK; Content-Type: application/json; {"users":[{"id":1}]}
REL|inferred|host:portal.example.com|calls_backend_api|host:api.example.com|Main JavaScript references https://api.example.com/v1
HYPOTHESIS|Portal and admin share session validation|Both set Domain=.example.com
```

### Step 1: explicit finding

The finding requests:

```text
grade=observed
severity=high
type=url
```

Severity ceiling for observed is critical, so high remains high. It receives a
random ID such as:

```text
8ab314df90c2
```

If the title is a full URL, graph projection creates:

```text
url node
host node
url --hosted_on--> host
```

If the title is descriptive rather than a URL, graph quality depends on parser
metadata; manual recording should use an explicit URL title/target when possible.

### Step 2: relation marker

Because the relation grade is inferred:

```text
calls_backend_api
→ hypothesis_calls_backend_api
```

The call upserts both hosts, adds a directed edge, and creates a separate
`evidence_grade=inferred`, `confidence=hypothesis` relation finding with
severity none.

### Step 3: hypothesis marker

The hypothesis becomes:

```text
finding_type=observation
confidence=hypothesis
grade=unverified
severity=none
```

It does not create a graph relation. The LLM may later confirm it:

```text
platform_graph_link(
  source="host:portal.example.com",
  target="host:admin.example.com",
  relation="shares_session_validation",
  evidence="The same session cookie authenticated both applications",
  evidence_grade="observed",
  derived_from="cookieFinding,authReplayFinding"
)
```

### Step 4: ranking

`api.example.com` may gain:

- API role points from configured regexes
- +8 per observed finding
- +12 for an observed HIGH
- Any operator boost

This score prioritizes further work; it does not alter evidence grade.

### Step 5: finalize

The unauthenticated endpoint is eligible as strong observed evidence if its
combined evidence is at least 80 characters or contains a configured marker with
at least 24 characters. The hypothesis relation remains in the hypothesis
section.

If no hard blockers remain:

```text
report_mode=complete
```

Otherwise:

```text
report_mode=partial_only
```

The report should quote finding `8ab314df90c2` as observed and label the session
relationship separately until confirmed.

---

## 25. Source map for maintainers

Evidence and findings:

- `backend/src/pentest_platform/schemas/finding.py`
- `backend/src/pentest_platform/services/evidence.py`
- `backend/src/pentest_platform/services/findings_store.py`
- `backend/src/pentest_platform/services/ingest_promoter.py`
- `backend/src/pentest_platform/services/parsers/freeform_probe.py`

Graph and cognition:

- `backend/src/pentest_platform/services/engagement_graph.py`
- `backend/src/pentest_platform/services/operator_memory.py`
- `backend/src/pentest_platform/services/finding_correlator.py`
- `backend/src/pentest_platform/services/graph_query.py`
- `backend/src/pentest_platform/services/crown_jewels.py`
- `backend/src/pentest_platform/services/evidence_chain.py`

Recall and context:

- `backend/src/pentest_platform/services/operator_recall.py`
- `backend/src/pentest_platform/services/commander_context.py`
- `backend/src/pentest_platform/services/open_loops.py`
- `backend/src/pentest_platform/services/context_delta.py`
- `backend/src/pentest_platform/services/stdout_index.py`

Execution:

- `backend/src/pentest_platform/services/tool_execution.py`
- `backend/src/pentest_platform/services/shell_exec.py`
- `backend/src/pentest_platform/services/script_exec.py`
- `backend/src/pentest_platform/services/job_store.py`
- `backend/src/pentest_platform/services/artifacts.py`
- `backend/src/pentest_platform/services/command_builder.py`

Reporting:

- `backend/src/pentest_platform/services/finalize_readiness.py`
- `backend/src/pentest_platform/services/finalize_rules.py`
- `backend/src/pentest_platform/services/report_outline.py`

Configuration:

- `config/ingest_rules.yaml`
- `config/correlation_rules.yaml`
- `config/parallelism.yaml`
- `config/finalize_rules.yaml`
- `config/thinking_model.yaml`

MCP/API:

- `platform-mcp/server.py`
- `backend/src/pentest_platform/api/v1/endpoints/hybrid.py`

---

## 26. Success definition

The LLM is elite when it:

1. Decides the next experiment from evidence.
2. Invents a custom probe when the catalog is insufficient.
3. Writes meaningful relations and tags into memory.
4. Preserves evidence and execution provenance.
5. Uses parallel branches without freezing the conversation.
6. Searches past evidence and attempts before repeating work.
7. Separates observations, inferences, and hypotheses.
8. Reports COMPLETE only when proof supports it.

The platform should remain a **lab + shared notebook + referee**, never a narrow
playbook.
