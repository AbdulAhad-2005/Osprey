# Plan 08 — Heuristic-Engine Docs De-scope

**Baseline:** `d7a4594` · **Risk:** Low (docs/draft-config only; no shipped code reads these) · **Depends on:** nothing.

## Why

The draft heuristic-engine design (5 untracked docs + 2 unwired configs) over-builds: it specifies an LLM-invented chaining scorer, a 45+ signal vocabulary, a honeypot gate, and a scope-validation gate — none grounded in real sources, and several containing outright bugs. Decision: chaining is the driver's job (raw output + `additional_args`), signals/honeypot/scope-gate are dropped. The design shrinks to what's actually kept: phase progression P0→P5, recon tool sequences, escalation *chains* (tool fallback), and a **minimal** P3→P4 gate. Confirmed: no Python imports `config/heuristic-engine.yaml` or `config/signal-detection-matrix.yaml`, so this is doc/config surgery with no runtime blast radius — but it must be coherent because it's the spec the future engine build will follow.

## Affected files
`docs/heuristic-engine-flow.md`, `docs/impl-spec-chaining-engine.md`, `docs/impl-spec-p3-p4-gate.md`, `docs/pentest-flow-design.md`, `docs/issue-18-rescoped.md`, `config/heuristic-engine.yaml`, `config/signal-detection-matrix.yaml`.

## Steps

### Step 1 — Remove the chaining engine
- Delete `docs/impl-spec-chaining-engine.md` entirely (the whole file is the chaining scorer being dropped).
- In `docs/heuristic-engine-flow.md`: delete §9.5 (P4.5 Chaining Engine) and the P4.5 node from the state machine (§14) and the signal `chain_detected`. Replace with one paragraph: "Chaining is performed by the driver (LLM or operator) using raw tool output and `additional_args`, not a deterministic scorer."
- In `config/heuristic-engine.yaml`: delete the `P4.5:` block (chain_patterns, scoring, steps).

### Step 2 — Remove the signal vocabulary
- In `docs/heuristic-engine-flow.md`: delete §3 (Signal Dictionary) and the "signal:" annotations sprinkled through the phase steps, OR reduce to the handful of *phase-gate* booleans actually kept (P0 scope_set, P1 live_urls/services, etc.). The 45-signal bus is dropped — the driver reads raw output. Keep only the phase-transition conditions that the kept P0→P5 progression genuinely needs.
- Delete `config/signal-detection-matrix.yaml` (the tech→tool dispatch it encodes duplicates the live `config/tech_dispatch.yaml`; if any of its mappings are better than `tech_dispatch.yaml`'s, port those rows into `tech_dispatch.yaml` first, then delete). Also: it names non-existent tools (`droopescan_scan` etc.) — do not port those.

### Step 3 — Remove honeypot + scope-validation gates; shrink P3→P4 gate to the minimum
- `docs/impl-spec-p3-p4-gate.md`: remove the Honeypot Detection filter and the Scope Validation Gate filter. The scope gate contradicts `docs/ARCHITECTURE.md:172` (which documents "no scope-based governance gate — deliberate"); removing it resolves that contradiction. Reduce the six-filter pipeline to the kept minimal set: **static-asset exclusion** + **minimum tool output** (drop parameter-reflection-gate too — it sends unpaced raw HTTP and mis-probes JSON/GraphQL; the driver decides reflection). Fix the doc's internal contradiction while here (it listed static-asset and content-type as separate filters despite the flow doc merging them — land the merged single "asset type filter").
- Update `config/heuristic-engine.yaml`'s `P3_to_P4_gate` block to match (remove honeypot_detection, scope_validation_gate, parameter_reflection_gate; keep static_asset_exclusion + a minimal-output check).

### Step 4 — Fix or delete the residual doc bugs
Any section that survives Steps 1-3 must be correct:
- Remove the `FindingType.SSQLI` typo and the mojibake keys (`"redirect可控"`, `"response差异化"`) — these were in the chaining spec being deleted, so Step 1 likely removes them; grep to confirm none remain.
- Remove references to the invented 19-value `FindingType` enum; the real schema (`schemas/finding.py`) has one `VULNERABILITY` bucket. Any surviving doc that assumed the fine-grained enum must be reworded to the real types.
- Reconcile phase vocabulary across the surviving docs (`heuristic-engine-flow.md` canonical P0-P5 vs the older 3-role model in `pentest-flow-design.md`/`issue-18-rescoped.md`). Either update the older docs to the canonical model or mark them clearly superseded and stop referencing them as design authority.

### Step 5 — State what's kept, cleanly
The surviving `docs/heuristic-engine-flow.md` should read as: P0→P5 phases, recon tool sequences, escalation chains (tool fallback on failure), "No Exploit No Report", breadth-before-depth, and a 2-filter P3→P4 gate — and explicitly note chaining/prioritisation/signal-reading are the driver's job. Target the ~500-line shape the maintainer wants, down from ~1935.

## Reconnect
No code reconnection (nothing imports these). The reconnection is *conceptual*: the surviving docs must not reference deleted sections (grep for `chain`, `signal`, `honeypot`, `scope_validation`, `crown_jewel`, `evidence_grade` across `docs/` and fix dangling references — several of these concepts are being removed by plans 02/03 too, so the docs must not describe them as live).

## Done criteria
- `docs/impl-spec-chaining-engine.md` and `config/signal-detection-matrix.yaml` deleted.
- `grep -rn "chain_detected\|SSQLI\|redirect可控\|honeypot_detection\|scope_validation_gate" docs config` returns nothing.
- `config/heuristic-engine.yaml` has no `P4.5` block and a minimal `P3_to_P4_gate`.
- Surviving docs reference no removed concept (evidence_grade, crown_jewels, signals, chaining) as a live mechanism.
- `docs/heuristic-engine-flow.md` reflects only the kept design and is internally consistent on phase names.
