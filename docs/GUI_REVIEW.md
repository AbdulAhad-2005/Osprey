# GUI architecture and evidence review — October 2026

## Large-engagement graph redesign — 21 October

The previous all-record diagram was still a poor starting point: on the NADRA
engagement it opened on a small region of a 1,339-record / 1,651-link canvas.
Keeping data accessible is necessary but does not by itself make a usable map.

The default is now a category overview that accounts for **every loaded record
and every valid stored relationship**, including same-category links and
hypotheses. It does not select a top eight/twelve sample. Categories are navigation
groups, not assertions that their members are equivalent. Select a category,
search/paginate its members, then explore an asset's direct connections. Two-hop
expansion and the full detailed topology remain explicit choices. The obsolete
ranked-subset implementation was removed. Overview positions are deterministic;
large detailed layouts retain the existing fast-layout safeguard. This follows
Cytoscape's [overview/subgraph exploration guidance](https://blog.js.cytoscape.org/2020/05/11/layouts/).
The fallback threshold was tightened to 150 drawn nodes after the real 267-node
grouped hierarchy exceeded the browser interaction deadline; it changes layout,
not record membership. Small neighborhoods have a balanced layout with fixed-size
cards so fitting the graph does not shrink labels unnecessarily.

Other changes address the data contract, not only layout:

- Relationship arrows now preserve source/destination. Previously `hosted_on`
  and `subdomain_of` were reversed for layout without changing their semantics.
  Parallel relationship records retain their original indices/provenance, and
  hypotheses cannot be collapsed into non-hypothesis links. The relationship
  inspector exposes counts, relation filters, search, pagination, source/destination
  navigation and original observation references.
- Graph risk badges and their attached finding references use one backend mapping
  and the same conclusion classifier as reports. Explicit primary asset references
  and IP targets are supported. Risk is not propagated to neighbors or siblings.
  Asset evidence confidence is labelled separately from finding confidence.
- Findings now provides explicit views for security conclusions, scanner signals
  and legacy review candidates. Original evidence and affected-target graph links
  are accessible from those views. These are presentation changes; no parser,
  confidence, policy, finding, or graph store record is changed.
- Reviewing a real account-takeover finding exposed incorrect DNS-remediation
  advice selected by the generic word `takeover`. Removed the keyword guessing
  table: authored remediation is retained verbatim and missing remediation is
  explicitly identified in both the GUI and exported report. Regression coverage
  checks ambiguous titles and preservation of recorded advice.
- Native fullscreen has a viewport fallback and exit control. Zoom, back navigation,
  direct/two-hop exploration, docked details, readable type labels, and preservation
  of the camera on same-view data refresh support longer investigations.

Existing records can represent the same address as both HOST and IP, and some old
HOST records contain narrative labels. The UI now explicitly counts stored records,
not unique machines, and displays their types. It does not silently rewrite identity
or discard historical evidence. Original graph API caps (5,000 nodes / 20,000 edges)
remain disclosed when reached; the overview is complete for the loaded projection,
not a claim of unlimited database coverage.

Validation: the graph/model tests cover exhaustive category membership, every edge
index, hypotheses, parallel provenance, direct/two-hop boundaries and a 5,000-record
fixture. Focused backend tests cover graph preservation and finding/risk mapping.
Browser verification uses saved engagements only; no target scans or exploitation
are part of this UI review.

Final browser pass verified the NADRA 1,339-record / 1,651-link graph in grouped
and ungrouped detailed modes, category-to-asset drill-down, back navigation,
fullscreen entry, button exit and Escape exit. The browser error log was empty.
The 23-record root neighborhood exposed another readability issue: a tall
two-column layout shrank labels when fitted. Balanced mode now uses four columns
above twelve neighbors, with a regression test for its bounds and stable ordering.
Both local dashboard and backend health returned HTTP 200 during the production
build. Frontend validation: 27 tests, typecheck and production build passed;
focused graph/report backend validation: 13 tests passed. No parser-confidence or
policy-enforcement changes were made.

Saved-data caveat: some historical graph relationships are semantically wrong
(for example, an SPF TXT value stored as a HOST with a `cname_to` relationship).
This presentation work preserves and exposes those records; it does not claim
to repair their ingestion or retrospectively validate scanner assertions.

## Follow-up review — 21 October

The first pass was not sufficient: its tiny default graph overview preserved
records in principle but made exploration unnecessarily difficult, and the
original development server was not included in the final availability check.

Port 3100 reproduced HTTP 500. Restarting only its local dev process restored
HTTP 200 without changing source. The earlier verification had briefly run a
production build in the same `.next` directory used by that process, leaving
inconsistent in-memory/on-disk build artifacts as the likely cause. No original
exception stack was available from that terminal, so this diagnosis is based on
the shared-output exposure and recovery behaviour, not a captured stack trace.
Development now uses `.next-dev`, while build/start share `.next`; an explicit
test-directory override remains supported. A normal production build completed
while ten concurrent requests to the running port 3100 all returned HTTP 200.
This uses Next's documented [custom output directory](https://nextjs.org/docs/pages/api-reference/config/next-config-js/distDir).
No source/cache directory was deleted to recover the server.

The broader follow-up addressed these independently verified feature gaps:

- Graph JSON itself merged asset identities, filtered static URLs and shortened
  labels before the browser received them. An opt-in record-preserving JSON
  projection now carries full labels, provenance and metadata; CLI/MCP defaults
  are unchanged. The saved NADRA example exposes 1,339 records instead of 1,240.
- All loaded assets are the default map, with reversible grouping and an
  ungrouped mode. Individual members can be expanded. The priority overview is
  optional. A readable target-centred camera avoids requiring a miniature full
  graph fit. Fit all/recenter, hierarchy/radial/grid layouts, type filtering,
  paged asset browsing and JSON download are available. Search shows every
  matching identity rather than arbitrarily opening the first match.
  A narrow-window test exposed synchronous hierarchical-layout stalls on the
  ungrouped 1,339-node map. Maps above 400 drawn nodes now use the cheaper grid
  strategy when hierarchy was requested, with an explicit explanation; focused
  maps retain hierarchy. This changes layout cost, not the set of records.
- Graph detail inspection exposes the actual relationship direction, full
  neighbors, metadata and original observation references. Counts distinguish
  loaded records, represented records and drawn nodes. Limits are explicit.
- Inventory summaries had lost routes to some deduplicated records and shortened
  legacy descriptions. All original references and sources now survive display
  merging. A shared, read-only inspector retrieves full original records on
  demand from inventory, findings and graph; it does not preload every evidence
  body into every view.
- A separate Evidence explorer pages/searches observations, scanner signals,
  all stored finding rows, legacy discoveries and execution notes without
  presentation filters. Pagination runs on the database, not a first-N download.
  Observation query paths now share one implementation. Original record reads
  remain pinned to the requested engagement.
- Missing reports return HTTP 404 instead of rendering a misleading empty
  assessment. Report assembly now discloses bounded-load limits. Structured
  views refresh after evidence changes and on focus; tool bursts are coalesced.
- Saving settings is disabled when the current configuration could not be read,
  avoiding replacement of an unknown configuration after a failed load.
- Launching a goal on an existing conversation previously ignored the goal;
  leaving it in the URL could repeat it on refresh. Goal dispatch now consumes
  the URL once and works with existing history. The launch page offers explicit
  fresh/reuse selection and refreshes the engagement list after binding.
- Background jobs were invisible after the chat driver stopped. The chat now
  displays job state, commands, progress logs and complete result inspection,
  with separate cancellation. Polling pauses when that tab is not visible.
  This does not change job execution or agent tool access.
- Browser verification found a React Strict Mode dialog lifecycle problem; the
  inspector no longer interprets effect cleanup as a user closing the dialog.
  Provider errors are displayed once rather than duplicated as a stopped reply.

Local verification used the real port 3100 and existing populated engagements,
plus `guiverification21`, explicitly labelled as a GUI regression engagement.
It generated no target traffic. A local sleeping Python job with ingestion
disabled was visible and cancelled from the GUI; its status became `cancelled`.
The configured free provider rate-limited the first harmless chat turn and
completed the next. Both appeared in the transcript; refreshing left exactly
two prompts, with no repeated URL goal and zero tool calls. This demonstrates
provider failure visibility as well as successful response persistence.
Final focused verification: 60 backend/shared-runner tests passed, 22 frontend
tests passed, and the production build passed while the development server
remained available. These are focused regressions, not the entire repository
test suite.

This is an operator console review, not a declaration that every backend tool
integration or every professional report requirement is now complete. Reports
cannot invent missing reproduction steps, owner-specific business impact,
assessor attribution, CVSS rationale or specific remediation. The evidence
inspector retains what exists, and limitations state what does not. Very large
graph/report projections remain bounded and disclose partial loads; original
finding/observation browsing is paginated. Job history shown in chat is the
latest 20 job records, not an unlimited execution archive. P0 policy enforcement
and parser-confidence rules have not been tightened or otherwise changed.

---

This review covers the operator console on `feat/gui-operator-console`, the
shared runner, transcript lifecycle, settings, report projection and graph
presentation. Changes are local; no commits, pushes or production deployment.
It is not a claim that every tool integration has been exercised against a
live external target.

## Architecture and data flow

The Next.js GUI is a same-origin client of FastAPI. One streaming proxy serves
JSON and SSE without implementing an independent pentest engine. The CLI and
backend foreground chat both use `agent_core.loop.Runner`. Typed execution
continues through the existing gateway, scheduler, evidence ingestion,
observations, findings and engagement graph. No tool catalogue or offensive
capability is removed by these changes.

For each engagement the backend owns one active chat task, independent of its
client connection. The in-memory event bus supplies immediate live updates;
the `chat_events` SQL journal supplies ordered replay using a monotonic cursor.
Public assistant narration, tool arguments/results, questions and termination
are durable. Spinner ticks are transient. GUI replay uses the same reducer as
live events. A message-ID boundary separates old text-only history from the
journal, avoiding timestamp-precision duplicates. Clearing/deleting an
engagement first settles its active task, then removes transcript records.

Settings update the project environment file. Configuration is re-evaluated
between idle turns; a changed configuration recreates runner budgets while
retaining conversation context. Active runs retain their starting configuration.

Findings, inventory and report use one canonical report projection rather than
three independent interpretations of legacy rows. The graph remains a
relationship projection, with equivalent neighborhoods grouped only for display.
All recorded members remain available through search/focus and the full map.

## Verified problems and remedies

- Chat originally persisted only prompts/final responses. Closing the tab lost
  tool cards and intermediate messages. A durable paged transcript now survives
  browser disconnects and backend restarts (the latter does not resume execution).
- Embedded gateway activation synchronously called back into its own HTTP
  server from the event loop. Activation now runs off that loop.
- A zero-event replay returned the entire history (`[-0:]`), allowing an old
  terminal event to end the next turn. Replay zero now means no replay, and
  subscribers register before replay begins.
- Concurrent tool results were displayed only after all siblings completed.
  Each now emits its completion immediately; cancellation awaits sibling cleanup.
- Fragile per-consumer SSE parsing could lose split frames. One shared parser
  handles chunk boundaries, Unicode and line-ending variants.
- Backend collection redirects could bypass the GUI origin. The shared proxy
  follows them server-side and preserves streaming responses.
- Blank settings fields could clear an existing custom base unintentionally;
  cached sessions could retain obsolete provider configuration indefinitely.
  Omitted values now stay intact and provider changes clear stale credentials.
  Single-line validation and quoted environment values preserve special characters
  and avoid duplicate-definition surprises. Keys remain server-side.
- Native backend startup could select a stale `backend/.env` rather than the
  root file. Root detection now agrees with the repository layout; explicit
  `OSPREY_ENV_FILE` supports isolated tests and custom deployments.
- A one-time health check left the GUI permanently offline after recovery.
  Visible pages now recheck readiness periodically and on focus.
- Legacy discovery rows inflated severity totals and overwhelmed the report;
  legacy inventory could conversely be empty. The report separates security
  conclusions, scanner claims, discovery facts and legacy review candidates.
  Malformed host labels are retained as unclassified discoveries, not counted
  as valid hosts. This is presentation normalization, not a parser-confidence
  change. No evidence or stored finding is deleted or downgraded.
- Large maps became unreadable when fitted wholesale. An adaptive small
  overview, grouped equivalent neighbors, raw-data search, focused connections,
  full labels, correct relationship directions in the inspector, and resize
  handling replace the initial hairball. Display caps are disclosed.
- Tables/findings now paginate; reports retain full evidence while keeping the
  on-screen appendix collapsed. Print styles expand supporting inventory, avoid
  clipped evidence and remove application navigation. Suggested remediation is
  distinguished from recorded remediation; observation references are retained.
- The graph/layout engine loads only when its tab is needed. Production build
  output for initial engagement-page JavaScript fell from about 367 KB to 219 KB.

## Report interpretation

The structure follows the separation of executive summary, scope, methodology,
technical evidence, remediation and limitations described in the
[OWASP WSTG reporting guidance](https://owasp.github.io/www-project-web-security-testing-guide/v41/5-Reporting/README).
Highest recorded technical severity is not an organizational risk rating or
GRC certification. Confidence is separate from impact. Draft status, failed
checks and unconfirmed conclusions are explicit. No CVSS score, business impact,
test coverage or successful exploitation is invented when absent from evidence.

The choice of focused subgraphs rather than fitting every asset at once is
consistent with [Cytoscape's layout guidance](https://blog.js.cytoscape.org/2020/05/11/layouts/).

An isolated copy of the populated local SQLite database was inspected:

| Saved engagement | Stored finding rows | Security conclusions | Legacy severity-labelled rows for review |
| --- | ---: | ---: | ---: |
| nadra.gov.pk | 998 | 0 | 9 |
| geo.tv | 119 | 1 | 2 |
| roburnabuilders.com | 491 | 17 | 62 |

These are classifications of existing stored types, not a fresh assessment or
endorsement of the claims. Potentially important legacy claims remain separately
reviewable rather than silently being discarded. No live scans of these targets
were needed to reproduce the presentation problems.

## Verification and limits

- Real configured free-model turn called only `platform_context`, then returned
  a response. Tool arguments/results and assistant text appeared live and again
  after refresh. A second run survived refreshing while active and completed in
  the reconnected page. No target traffic was requested in these chat tests.
- Backend regressions cover cursor scoping, durable disconnected-run output,
  legacy boundaries, no-model errors, settings omission/provider switching,
  special-character persistence, report classification and inventory normalization.
- Frontend regressions cover SSE split-byte/newline framing, reducer ordering and
  graph grouping/focus bounds. Shared-runner regression verifies fast tool
  completion before a slow sibling and cancellation cleanup.
- Final focused verification: 42 backend/shared-runner regressions passed across
  the focused runs, 16 frontend tests passed, and the production GUI build passed.
  Storage-failure coverage verifies that clients receive termination even if
  journaling fails.
- SQLite migrations and a disposable PostgreSQL migration database were checked.
- Browser checks use the isolated backend/database, not the original running
  service. Report JSON/Markdown counts were compared for all three engagements.
- A wider graph test expects HOST for a bare name, but the existing canonical
  host policy deliberately infers DOMAIN/SUBDOMAIN. That pre-existing expectation
  is unrelated to these display changes and is recorded rather than changing
  host identity policy in a GUI patch.

Remaining boundaries: the console is local/single-instance, not a multi-tenant
service. Backend process restarts cannot resume in-flight Python tasks. Old tool
events that were never persisted cannot be reconstructed. Keys being configured
does not prove provider connectivity or tool-calling support. Display limits are
not pentest execution limits. Report quality still depends on the operator filing
well-supported conclusions and recording finding-specific remediation. Browser
print layout should also be reviewed in the user's chosen PDF printer before
external delivery.
