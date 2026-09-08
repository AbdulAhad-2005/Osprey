---
name: full-attack-surface-pipeline
description: "Methodology for widening a seed domain into a full attack-surface map: a suggested order (not autopilot), with the graph and tree as the source of truth for coverage."
phases: [pipeline]
tags: [pipeline, methodology]
---

# Full Attack Surface Pipeline

Methodology for widening a seed domain into an attack-surface map. Stages are a
**suggested order**, not an autopilot script. The attack-surface tree, network
surface, and graph are the source of truth for what is done vs what might remain
— not a separate gap list.

## How this fits the loop

1. `platform_context` → read the attack-surface tree, network surface, and
   phase-readiness signal
2. Pick **one** next action based on what the tree/graph shows is missing
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
  ├── STAGE 6: CDN/WAF-origin bypass ────────── direct-to-origin, DNS history, TLS, headers
  ├── STAGE 7: Historical URLs ──────────────── waybackurls / gau
  └── STAGE 8: Light web crawl ──────────────── high-value hosts only
       └── TREE: use platform attack_surface_tree (not hand-built)
```

## Stage detail

### Stage 1 — Sister domains

**Tool:** `domain_hunter`
**Params:** `domain=<seed>`, `confidence_min=medium`
**Output:** Affiliated roots → graph (`affiliated_with`)

Do **not** auto-fan-out. Use `platform_graph_query` to see what's already enumerated, or
an explicit `platform_fanout` preview.

### Stage 2 — Subdomain enumeration

**Tool:** `subfinder_scan` (alternatives: amass / fierce / dnsenum)
**Run on:** Seed + sisters found in Stage 1 — check `platform_attempts` first so you
don't blindly re-run what's already been tried
**If thin:** Try another source (amass/crt.sh) before concluding the surface is exhausted

### Stage 3 — Live HTTP probe

**Tool:** `httpx_probe`
**additional_args (example):** `"-sc -title -td -fr -ip"`
Cloudflare/WAF signals here feed Stage 6 — a fronted host is a bypass candidate, not
something to skip.

### Stage 4 — IP mapping

Prefer graph `resolves_to` / tree IPs over re-resolving everything. Shared IPs → `co_hosts`.

### Stage 5 — Port / service (per IP)

Read **Network Surface**: `ports_known` vs `services_known`. Any IP without either is
your next action — syn/rustscan/naabu first, then service scan with the discovered ports.
Full `-p-` / `1-65535` is allowed — prefer targeted ranges for speed, run full when useful. Honor an explicit operator constraint.

### Stage 6 — CDN/WAF-origin bypass

Not optional for a CDN-fronted target — part of the recon job, not a nice-to-have.
Direct-to-origin probes, DNS history, TLS certificate matching, header analysis,
`origin_ip_attribution`, `cdn_origin_probe`.

### Stage 7 — Historical URLs

`waybackurls_discovery` / `gau_discovery` on live hosts when in scope.

### Stage 8 — Light crawl

Prioritize admin/API/staging — not every host.

## Rules

- **Skip stages** the tree/graph already cover, or the user excluded.
- **One next step** at a time.
- **Deduplicate** shared IPs; do not rescan blindly — check `platform_attempts` first.
- **If a tool fails,** try improving the arguments by analyzing the issue and solving it, try an alternative once, then move on.
- **Evidence lives in the platform** — prefer the tree/graph over chat memory.
