---
name: adversarial-review
description: "Before calling an engagement done: argue against your own coverage, framed as auditing someone else's checklist-driven work. Counters checklist-satisficing — the single most-cited failure mode in 2026 research on AI pentesting agents."
phases: [recon, vuln, web, exploit]
tags: [shared, review, coverage, curiosity]
---

# Adversarial self-review

The most common way an autonomous pentest goes shallow isn't a missing tool — it's an agent
that works a systematic pass, finds nothing new for a while, and reports done. Research on
AI pentesting agents converges on this exact pattern (checklist-satisficing: the agent that
methodically works a list stops noticing what the list doesn't cover). The fix isn't a longer
checklist — a longer list still has edges. The fix is a different reasoning stance, run once
before you actually call it done.

## Do this as a stance, not a checklist

Read `platform_context()` fresh, then answer this **as if you are a different, more skeptical
person auditing someone else's work**, not reviewing your own:

> *"Someone ran a systematic pass on this engagement. What's the one thing a systematic pass
> reliably misses?"*

That framing matters — reviewing your own work under your own framing tends to just re-confirm
your own priors (you don't doubt a decision you don't remember making as a decision). Auditing
"someone else's" work makes the gaps easier to actually see.

Concrete places checklists systematically miss, to prompt the reasoning (not to re-run as a
list — use these to think, not to tick):

- **The unglamorous endpoint nobody re-checked.** An early scan hit a dead end on some path and
  moved on — was that dead end re-tried after later recon changed what you knew (a new
  parameter, a new auth token, a tech-stack identification that changes what "dead end" even
  means)?
- **A severity assigned early, never revisited.** A finding graded LOW/MEDIUM when it was first
  seen, before three other findings on the same asset arrived — does it still read as LOW now
  that you know more about what's actually reachable from it?
- **A peer host behaving differently for no explained reason** — `platform_anomalies` surfaces
  this mechanically; read it here explicitly rather than assuming it would have come up
  naturally.
- **The thing you decided was "probably fine" without checking.** Every engagement has at least
  one — a login form assumed to have rate limiting because it looked standard, a subdomain
  assumed to be a CDN edge because of a header, an API assumed internal-only because it wasn't
  linked from the UI. "Probably fine" that was never actually tested is exactly what this stance
  exists to catch.

## What to do with the answer

If the honest answer is "nothing, I'd chase the same things" — that's a legitimate outcome, not
a failure to find something. Say so and finalize. If it surfaces something real, chase it before
reporting done — one more targeted action, not a reason to restart the whole engagement.

This is a one-time gut-check before finalizing, not a phase to repeat after every tool call —
running it constantly would just make it another checklist item people stop actually reasoning
about.
