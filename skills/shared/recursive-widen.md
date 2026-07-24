# Recursive expansion (universal)

Load once. Re-use on any phase. Do not re-load.

## Core rule

After every tool run: **did it find anything NEW?**

The graph tells you. If the tool produced new findings (new domains, hosts, IPs,
ports, URLs, services) that weren't in the graph before, those new assets need
their own expansion before you move on.

## Expansion map

| New asset found | What to run next |
|---|---|
| New root domain | `domain_hunter` + `subfinder_scan` on it |
| New hostname | `dnsx_resolve` → if resolves, `httpx_probe` |
| New IP | `naabu_port_scan` (top 1000) |
| New open port | `nmap_service_scan` or `platform_script` banner grab |
| New URL | `httpx_probe` for tech, `gau_discovery` for history |
| New tech/banner | `platform_script` for deeper probe |

Each of those may produce more new findings → loop back.

## Persist the expansion, not just the discovery

A tool run that finds 30 new subdomains but links 0 of them into the graph hasn't
really expanded the map — it's left 30 islands. After any tool that returns a
list, call `platform_graph_link_many` once for the whole batch (fan form: one
`source` + `relation` + `targets=[...]`). Don't skip this because 30 individual
calls felt expensive — it's one call now.

## When to stop

When a tool run produces **zero new findings** — everything in the graph has
already been explored at the appropriate depth **and** linked. Graph is stable.
Check `platform_finalize_check` — it now reflects back on unexplored/orphan
nodes and untested hypotheses rather than just gating a report; treat what it
shows as the last look-back before you actually stop.

## This prevents

- Finding an IP in Shodan but never port-scanning it
- Finding a sister domain but never running subfinder on it
- Opening a port but never version-scanning it
- Finding a URL but never probing its tech/paths
- Going deep on one branch while leaving other branches completely unexplored

The graph is your map. If a node exists without outgoing edges of the expected
type, it's unfinished work.

## "Same IP cluster" is not a reason to skip

Crown jewels tell you where to start, not where to stop. "These 15 subdomains
probably resolve to the same firewalled cluster we already tested" is a guess
about IPs, not the applications on them — virtual hosting means different
subdomains on one IP routinely serve completely different apps, paths, and
tech stacks. Don't let a shared IP/cluster grouping talk you out of at least
one pass (httpx probe, tech fingerprint) on each host. Every asset can still
produce a result.
