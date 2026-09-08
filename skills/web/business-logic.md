---
name: business-logic
description: "Business-logic testing (WSTG-BUSLOGIC): reason about the rules the app should enforce and test them with browser_flow and replayed requests; the highest-value web testing."
phases: [web]
tags: [web, business-logic]
---

# Business logic testing (WSTG-BUSLOGIC)

Business-logic flaws are where the best findings live and where scanners are blind — no tool
knows your target's *rules*. **You** reason about what the application is supposed to enforce;
`browser_flow` (and replaying captured requests) is how you test it. This is the highest-value
part of web testing.

## Method

1. **Understand the flow first.** `browser_scrape` + `browser_flow` to map the real
   multi-step processes: registration, login, cart→checkout→payment, fund transfer, role
   changes, file upload, approval workflows. Note the intended sequence and the invariants
   (what MUST be true: "price ≥ 0", "can't ship before pay", "user A can't see user B's order").
2. **Identify the trust boundary.** Where does the client send state the server should
   re-validate? Prices, quantities, user IDs, roles, step tokens, totals — anything the browser
   controls that the server might trust.
3. **Attack the invariants, one at a time.** For each rule, construct a flow that breaks it and
   assert the outcome:
   - **Parameter/price tampering** — intercept/replay the request with `qty=-1`, `price=0`,
     `amount=0.01`, `role=admin`, another user's `id`. (Capture the request with `browser_flow`
     network capture, then replay via `platform_script` with the tampered value.)
   - **Step / sequence bypass** — skip a step (go straight to the confirmation URL), reorder
     steps, or replay a one-time step token twice.
   - **Function/limit abuse** — apply a coupon N times, exceed a quota, negative quantities,
     integer overflow on totals.
   - **State transition abuse** — cancel-after-ship, refund-then-keep, re-use an expired token.
4. **Race conditions** — fire the same state-changing request many times concurrently
   (`platform_script` with parallel requests) — double-spend, coupon reuse, balance races.
5. **Assert the impact.** Did the app accept the illegal state? Use `assert_text` / re-read the
   resulting page/API to confirm the invariant actually broke (money moved, access granted).

## Turning it into a finding

- The finding is the **broken rule + its impact**, not the tool output. "Checkout accepts
  quantity=-1, crediting the account $X" — with the reproducing flow/requests as evidence.
- Severity is business impact (financial loss, data exposure, auth bypass), graded OBSERVED
  because you drove it and confirmed the state change.
- If you only *suspect* it (couldn't confirm the state changed), it's INFERRED — say so.

## What needs a browser vs a script

- **Browser (`browser_flow`)** — anything stateful/multi-step: reach the vulnerable state, hold
  the session, observe the result.
- **Script (`platform_script`)** — replaying a single captured request with a tampered value, or
  firing concurrent requests for a race. Grab the exact request from `browser_flow`'s captured
  API calls, then script the variation.

## Do not

- Perform real destructive/financial transactions on a live system without explicit written
  scope — proving you *can* reach the state is often enough; completing the fraud is not.
- Assume a flaw from a single run — confirm the invariant broke and that it's repeatable.
- Test other users' data/accounts beyond the authorised test accounts.
