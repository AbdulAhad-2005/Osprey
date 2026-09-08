---
name: query-back-loop
description: "The query-back loop: flush and re-read memory and graph on triggers (roughly every three tool calls, or on new assets) so context stays current."
phases: [shared]
tags: [methodology, memory]
---

# Query-back loop

Load once. Do not re-load.

## The loop — three triggers, one flush + two reads

Run this whenever ANY of these is true, not just on a fixed cadence:
- every ~3 tool calls
- you're **stuck** (a tool keeps failing, you're circling, unsure what's next,
  about to ask the user a question you might already know)
- you think you're **about to finish**

```
0. flush your reasoning        → one bulk call for anything you concluded but no
                                 tool emitted (platform_record_findings /
                                 platform_graph_link_many / platform_think)
1. platform_thinking          → shows untested hypothesis cards from evidence
2. platform_context           → phase-readiness, crown jewels, jobs, dispatch signals
```

Step 0 is the whole discipline: tool/script/shell output is already stored
automatically, so you do NOT flush that. You flush only the conclusions living in
your head — an interpretation, a relationship you worked out, a hypothesis — and
you do it here, at the checkpoint, in ONE bulk call. Never pause mid-probe to
record, and never re-record a fact a tool already printed (it's a harmless no-op,
just wasted effort).

Then pick the highest-value hypothesis card or crown jewel. Run one tool against it. Repeat.

## Memory augments your context — it doesn't replace it

The database is never guaranteed complete; it only knows what got persisted.
Your own live reasoning still matters. Use both together: query memory for
what's stored, but also trust and act on what you've worked out yourself this
session — then persist that reasoning so it survives past this turn.

## Checking where you are

```
platform_finalize_check  (or platform_pipeline)
```

Shows the conductor's phase-readiness: recon status, whether vuln/exploit have
unlocked (with the evidence that unlocked them), and any recon-reopen candidates.
This is informative, not a gate — you decide what to do with it. If you believe
the surface is genuinely exhausted, say so and check with the user rather than
silently deciding either way.

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
