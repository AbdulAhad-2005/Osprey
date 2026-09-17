# Plan 05 — Rigid Wrappers & Silent Overrides → Advisory

**Baseline:** `d7a4594` · **Risk:** Low (small, independent fixes) · **Depends on:** nothing.

## Principle

A mechanism may **hard-block** only when it is a genuine authorization boundary (Rules-of-Engagement gating destructive/exploit tools) or a resource-safety cap that protects the target/infra. Everything else computes a signal and lets the driver decide. These four each violate that and should become advisory or honestly-configurable. Fix the mechanism, not the symptom.

## Fix 1 — `naabu_port_scan` hard-rejects wide ranges pointing to a non-existent option
`mcp-servers/network/tools/naabu_port_scan.py:33,49-55`: raises `ValueError` for any range >5000 ports and tells the caller to use "an approved full scan" that exists nowhere.
- **Fix:** remove the hard rejection. A full/wide range is a legitimate move a driver may choose. If a resource-safety ceiling is genuinely wanted, make it a *large* default that is (a) overridable via a parameter and (b) auto-routed to a background job (the codebase already has `platform_job_start` for slow scans) rather than refused. Do not invent an "approved scan" flag — either allow it (preferred) or background it.
- Remove the dangling reference to the non-existent option in the error/help text.

## Fix 2 — `hydra_attack` hardcodes thread count
`mcp-servers/creds/tools/hydra_attack.py:45`: `-t 4` hardcoded, no override.
- **Fix:** expose `threads` as a real parameter with a sane default (keep 4 as default — brute-force politeness), passed through to `-t`. The driver can raise it when RoE and target allow. Do not rely on the `additional_args` "last flag wins" accident — make it a first-class param so it's discoverable.

## Fix 3 — `learned_skills._reject_if_duplicate` hard-rejects before human review
`backend/src/osprey/services/learned_skills.py:41-45,101-123`: a Jaccard similarity ≥0.72 raises `LearnedSkillError`, so a proposal never reaches the operator who is supposed to be the approval gate.
- **Fix:** turn the similarity check from a **rejection** into an **advisory flag** on the proposal ("similar to existing skill X, score 0.74") that is surfaced to the operator at approval time. The operator decides; the code does not pre-filter. Keep the computation, drop the raise. (This preserves the platform's own stated "operator approves" design instead of undermining it.)
- If a true *exact* duplicate (score 1.0 / identical body) should still auto-reject, that's a defensible resource guard — but 0.72 is not exact. Only auto-reject on effectively-identical content, and even then return a clear message, not a bare error.

## Fix 4 — `parallelism_config.load_parallelism()` silently overrides the config file
`backend/src/osprey/services/parallelism_config.py:44-47`: clamps `max_running_jobs`≤16, `agent_spawn_budget`≤500, `max_spawn_depth`≤8 regardless of what `config/parallelism.yaml` says; `job_store.py:354-377` then hard-raises at the clamped ceiling. The config file is readable and looks authoritative but the enforced value differs — actively misleading.
- **Fix:** the config file must be the truth. Either (a) honour the configured value (remove the silent clamp; keep only a very high sanity ceiling to prevent absurd values, and *log a warning* when it triggers, naming the file and the value), or (b) if a hard ceiling is a real infra-safety requirement, document it in `config/parallelism.yaml` itself as a comment AND log at load time when the file's value exceeds it, so the operator is never lied to. Prefer (a). Never silently rewrite a value the operator set.

## Reconnect
- Fix 1/2: verify the tool's typed signature in `platform-mcp/typed_recon_network.py` / `typed_*` (and `tool_registry.py`) exposes the new/loosened params so the driver can actually pass them.
- Fix 4: any code reading the clamped values (`job_store.py:354-377`, `fanout_assets.py`, `surface_expansion.py`, `phase_agent.py` concurrency) now sees the honest value — confirm none assumed the ≤16 ceiling as an invariant.

## Done criteria
- `naabu_port_scan` with `1-65535` runs (backgrounded if slow), does not raise.
- `hydra_attack(threads=16)` passes `-t 16`.
- A near-duplicate learned-skill proposal reaches the operator with an advisory note instead of raising.
- Setting `max_running_jobs: 50` in `config/parallelism.yaml` results in 50 (or a logged warning naming the enforced ceiling) — never a silent 16.
- `cd backend && python -m pytest tests/ -q` passes.
