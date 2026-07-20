# Full Attack Surface Pipeline

Methodology for widening a seed domain into an attack-surface map. Stages are a
**suggested order**, not an autopilot script. The platform’s `coverage_gaps`,
attack-surface tree, and network surface are the source of truth for what is
done vs what might remain.

## How this fits the Commander loop

1. `platform_context` → read **coverage gaps (advisory)**, tree, network surface
2. Pick **one** next action (tool or ignore a low-confidence gap)
3. `platform_exec` → findings land in Postgres graph (per engagement)
4. Re-read context — do not rebuild the tree in chat

Optional: `platform_fanout(action="enumerate_sisters")` with `dry_run=true` first;
execute only with `confirm=true`. Never silent after `domain_hunter`.

## Suggested stages

```
Seed Domain
  ├── STAGE 1: Sister domains ───────────────── domain_hunter
  ├── STAGE 2: Subdomain enum ───────────────── subfinder (seed + pending sisters)
  ├── STAGE 3: Live HTTP probe ──────────────── httpx (-sc -title -td -fr)
  ├── STAGE 4: DNS / graph IPs ──────────────── resolves_to / co_hosts in graph
  ├── STAGE 5: Port + service (per IP) ──────── nmap_syn / rustscan → nmap_service
  ├── STAGE 6: Cloudflare / WAF (optional) ──── CF gaps are soft; origin hunt optional
  ├── STAGE 7: Historical URLs ──────────────── waybackurls / gau
  └── STAGE 8: Light web crawl ──────────────── high-value hosts only
       └── TREE: use platform attack_surface_tree (not hand-built)
```

## Stage detail

### Stage 1 — Sister domains

**Tool:** `domain_hunter`
**Params:** `domain=<seed>`, `confidence_min=medium`
**Output:** Affiliated roots → graph (`affiliated_with`) + soft `sister_unenumerated` gaps

Do **not** auto-fan-out. Use context gaps or explicit `platform_fanout` preview.

### Stage 2 — Subdomain enumeration

**Tool:** `subfinder_scan` (alternatives: amass / fierce / dnsenum)
**Run on:** Seed + sisters that still show soft `sister_unenumerated` / `root_unenumerated`
**If thin:** Escalate carefully; unstructured empty runs may already be marked in tool_coverage

### Stage 3 — Live HTTP probe

**Tool:** `httpx_probe`
**additional_args (example):** `"-sc -title -td -fr -ip"`
CF signals set soft `host_cf_no_origin` gaps — optional follow-up only.

### Stage 4 — IP mapping

Prefer graph `resolves_to` / tree IPs over re-resolving everything. Shared IPs → `co_hosts`.

### Stage 5 — Port / service (per IP)

Read **Network Surface**: `ports_known` vs `services_known`.
Gaps: `ip_unscanned` → syn/rustscan; `ip_ports_no_service_scan` → service scan with ports.
**Never** `-p-` / `1-65535` unless the user allows.

### Stage 6 — Cloudflare / WAF

Optional. Soft gap only; do not force origin discovery out of scope.

### Stage 7 — Historical URLs

`waybackurls_discovery` / `gau_discovery` on live hosts when in scope.

### Stage 8 — Light crawl

Prioritize admin/API/staging — not every host.

## Rules

- **Gaps are advisory** — confidence < ~0.4 often means parse miss; verify first.
- **Skip stages** the tree/gaps already cover or the user excluded.
- **One next step** at a time; do not execute every gap.
- **Deduplicate** shared IPs; do not rescan blindly.
- **If a tool fails,** try improving the arguments by analyzing the issue and solving it ,try an alternative once, then move on.
- **Evidence lives in the platform** — prefer tree + gaps over chat memory.
