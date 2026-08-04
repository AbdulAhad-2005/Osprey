# Asset Discovery — Breadth Before Depth

The failure mode this skill exists to prevent: you enumerate 50 subdomains, deep-dive 5
of them (ports, tech, JS, params), then stop or summarize — 45 hosts never probed. Real
attack surface is *wide* (forgotten hosts, staging, acquisitions, infra with no DNS name),
and the win is usually on a host you never looked at, not a fifth tool run against one you
already own.

Two rules govern everything below:

1. **Breadth first.** Probe EVERY live host at least shallowly (httpx + a fast port sweep)
   before deep-diving ANY single host. A shallow pass over 50 hosts beats an exhaustive
   pass over 5.
2. **Loop until the set stops growing.** Every new name, PTR result, CNAME target, and
   cert SAN is a fresh seed. Feed it back into discovery. Discovery is *done* when a full
   pass adds nothing new — not when you get bored or the context fills up.

## The convergence loop

```
seed(s) ──► enumerate ──► resolve ──► probe live ──► extract new names ──┐
   ▲                                                                      │
   └──────────────── any new names? keep looping ◄───────────────────────┘
```

Run it as: enumerate → resolve → probe → harvest new seeds → repeat. Stop when a pass
yields no new assets.

## Stage 1 — enumerate (widen the seed)

- `subfinder_scan` (domain=) — passive aggregation across many sources incl. CT
- `crt_sh_query` (domain=) — certificate transparency; catches names brute force misses
- `amass_scan` (domain=, `additional_args:"-passive"`) — second source when inventory looks thin
- `domain_hunter` (domain=) — sister / acquisition / affiliate roots → each is a new seed
- `dnsenum_scan` (domain=) — DNS enum; also auto-attempts AXFR (a working zone transfer
  hands you the entire namespace in one shot — high value, always worth the try)

Cross-source: CT + subfinder + amass together beat any single source. Never trust one.

## Stage 2 — resolve and pivot (the leads brute force never finds)

- `dnsx_resolve` (target=host list) — bulk forward resolve; **keep CNAME chains** — they
  reveal third-party providers, CDNs, and takeover candidates.
- `tlsx_inspect` (target=) — read live cert SANs/CN. One cert often lists many hostnames
  (api + admin + internal + marketing). **Every SAN is a new seed.** Internal-looking SANs
  (`*.internal`, `*.svc.cluster.local`, staging names, RFC1918-style names on a public
  cert) are the highest-signal leads in the whole engagement.
- **Reverse DNS (PTR)** — not yet a typed tool. Do it via `platform_script` / `platform_shell`:
  `dig -x <IP>` or `host <IP>` on each resolved IP. Co-located hostnames on a shared IP
  surface here and nowhere else.
- **ASN / netblock** — not yet a typed tool. Via `platform_script`:
  `whois -h whois.cymru.com " -v <IP>"` maps an IP to its ASN + announced prefix. If the
  org runs its own ASN, treat every announced prefix as candidate assets and sweep them.
  (For cloud-hosted targets the IP belongs to AWS/Azure/GCP, not the org — pivot via
  cert/vhost instead of netblock; don't scan the provider's range.)
- `cdn_origin_probe` / `origin_ip_attribution` — separate edge from origin before you scan,
  so you don't burn budget on CDN edges. See `ip-attribution`.

## Stage 3 — probe live (breadth pass, ALL hosts)

- `httpx_probe` on the **entire** deduped host list at once (batch job via
  `platform_job_start` if large). Capture status/title/server/tech in one pass. Each host
  that serves content is confirmed surface; each grabbed SAN feeds back to Stage 1.
- `naabu_port_scan` (top ports) across all live hosts — a fast sweep, not a full nmap.
  Non-HTTP services (DBs, caches, brokers, mgmt ports) live here.

Only AFTER every host has this shallow pass do you rank and deep-dive.

## Stage 4 — classify, rank, then deep-dive the top of the list

Cluster hosts by **function** (app, API, auth, admin, CI/CD, observability, storage, VCS,
mail), not by product. Rank by exposure × value. THEN deep-dive the top few with
`nmap_service_scan`, `tech_stack_analyze`, content discovery (`feroxbuster_scan`), and JS
analysis (`js_recon`, `katana_crawl`). The 45 hosts you shallow-probed are now ranked, not
forgotten — the graph and `platform_context` coverage gaps hold them for you.

## Advanced pivots (cheap breadth multipliers)

- **Cert-fingerprint pivot** — when Shodan/Censys keys exist, search by a cert's
  `fingerprint_sha256` to find every host presenting the SAME cert. Strongest link for
  tying acquisitions and shadow infra to the target. Via `shodan_search`.
- **Favicon / response hashing** — the same favicon hash across unrelated hostnames
  clusters instances of one app (`httpx -favicon` via `additional_args`, pivot the hash in
  Shodan).
- **Vhost differentials** — probe a single IP with several `Host:` values (`ffuf_scan`
  mode=vhost) to unmask co-located apps hidden behind one address.
- **Naming-convention inference** — wildcard SANs (`*.corp.example.com`) expose the org's
  scheme even when hosts resolve privately. Seed targeted guesses (`grafana.corp`, `ci.corp`,
  `vault.corp`) instead of blind brute force.

## Using the platform to hold breadth for you

You cannot keep 50 hosts in working memory. Don't try — let the system track them:

- After each batch, `platform_graph_link_many` the discovered assets so the graph, not your
  context window, is the inventory of record.
- Call `platform_context` for coverage gaps + crown jewels rather than re-listing hosts
  yourself. If it says "38 subdomains unresolved," that's your next breadth action.
- When you feel the urge to stop, run `platform_context` first — the gap it names is almost
  always a host you shallow-probed and never returned to.

## Do not

- Deep-dive host #1 before host #50 has had a shallow probe.
- Stop discovery because context is filling — offload to the graph and keep looping.
- Treat a passive/CT hit as a live asset — confirm with `httpx_probe` before any HIGH claim.
- Scan a cloud provider's whole netblock as if the org owned it.
- Inflate the surface with CDN edges, vhost aliases, or stale historical DNS — dedupe to
  distinct origins and record which source produced each asset.
