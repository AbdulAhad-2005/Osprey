# Query-back loop (prevents early stop)

Load once. Do not re-load.

## The loop — three triggers, same two calls

Run this whenever ANY of these is true, not just on a fixed cadence:
- every ~3 tool calls
- you're **stuck** (a tool keeps failing, you're circling, unsure what's next,
  about to ask the user a question you might already know)
- you think you're **about to finish**

```
1. platform_thinking          → shows untested hypothesis cards from evidence
2. platform_context           → shows open gaps + crown jewels + jobs + look-back
```

Pick the highest-value gap or hypothesis card. Run one tool against it. Repeat.

If both return nothing → only then move toward finalize.

If a tool call just returned a list (subdomains, IPs, ports, techs), link them
into the graph with one `platform_graph_link_many` call before you move on —
don't leave them as chat-only output.

## Memory augments your context — it doesn't replace it

The database is never guaranteed complete; it only knows what got persisted.
Your own live reasoning still matters. Use both together: query memory for
what's stored, but also trust and act on what you've worked out yourself this
session — then persist that reasoning so it survives past this turn.

## Before you stop (or when stuck)

```
platform_finalize_check
```

This is a look-back, not a gate: it surfaces unexplored/orphan graph nodes and
untested `platform_think` hypotheses you haven't followed up on yet. Read what
it shows, pick the highest-value item, deepen it, then re-check.

A clean result only means nothing **stored** is missing — it cannot see your
own reasoning. Before you actually stop, ask yourself: did I conclude or
notice anything this session (a pattern, a relation, a suspicion) that never
got written down? If yes, persist it now (`platform_record_finding` /
`platform_think` / `platform_graph_link_many`), then re-run the check. Only
move to `platform_report_outline` once it comes back clean or you can name why
the remaining items don't matter.

## On hypothesis → always persist

```
platform_think(
  hypothesis="what you suspect",
  evidence="signal seen",
  plan="next probe to test it"
)
```

Then later: was it confirmed or blocked? Record with `platform_record_finding` or another `platform_think` indicating result.

## On failure → check attempts before re-try

```
platform_attempts(asset="host.name")
```

Change params, force_refresh, or switch approach — don't repeat the same dead end.
