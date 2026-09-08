---
name: defense-evasion-overview
description: Awareness of what generates detectable telemetry (AV/EDR, logs) during a post-exploitation engagement, so activity stays deliberate rather than accidentally noisy. Use when an engagement explicitly tests detection/response (red-team emulation) or when avoiding unnecessary noise on a live production host. Do not use to build genuinely undetectable malware or to justify hiding activity from the client — see shared/governance-rules.
phases: [defense-evasion, post-exploitation]
tags: [edr, logging, opsec]
mitre: [T1027, T1070, T1055.001]
requires_tools: []
---

This is awareness, not a weaponization guide: knowing what's loud helps you avoid unnecessarily
disrupting a live production host during a standard engagement, and is the actual subject matter
on a red-team engagement that's explicitly testing detection/response. It is never license to hide
genuine activity from the client — every action still gets recorded as evidence regardless of
whether it would evade a real defender.

## What generates signal

- **Command-line logging** (Windows Event ID 4688 with command-line auditing, or Sysmon Event ID
  1) captures full process command lines — a `certutil -urlcache -f <url> payload.exe` or a
  base64-encoded PowerShell `-EncodedCommand` is exactly the kind of string that trips a detection
  rule; know this generates evidence, don't rely on it being invisible.
- **AV/EDR static signatures** flag known-bad binaries/scripts by hash or pattern. Living-off-
  the-land (using binaries already present and trusted — `certutil`, `bitsadmin`, `mshta`,
  `rundll32`, PowerShell, `curl` on modern Windows) generates less signature-based signal than
  dropping a custom compiled binary, simply because the binary itself isn't inherently suspicious
  — the *behavior* is what a decent EDR actually keys on.
- **Process injection / in-memory execution** (reflective DLL loading, process hollowing) avoids
  writing a payload to disk (defeats on-disk AV scanning) but is exactly what EDR behavioral
  detection (API hooking, ETW) is built to catch — it is not a bypass against a modern EDR, only
  against pure signature AV.
- **Network telemetry** — DNS queries to freshly-registered/unusual domains, beaconing at regular
  intervals, and plaintext C2 are all standard detection-rule fodder; HTTPS to a domain that
  otherwise looks legitimate blends into normal traffic far better than a raw TCP callback.

## Practical guidance for THIS platform

- Prefer already-present tools (`curl`, `python3`, standard Kali binaries already invoked via
  `platform_shell`) over dropping custom compiled payloads, simply because it's less disruptive to
  a live host — not to defeat a specific product.
- On a production host during a standard (non-red-team) engagement, default to the **quietest
  path that still proves the point** — this is a scope/impact discipline, not evasion tradecraft.
- On an explicit red-team/detection-testing engagement, the goal flips: generate realistic
  adversary telemetry on purpose so the client's detection stack has something real to catch —
  document exactly what was done and when, so it can be correlated against their alerts
  afterward. Coordinate timing with the client's IR/blue team per the engagement's rules, per
  `shared/governance-rules`.

## Do not

- Attempt to genuinely evade a client's production EDR/AV as an end in itself outside an
  explicitly scoped red-team engagement — that's not what a standard pentest needs, and it
  burns time that should go to finding and proving real vulnerabilities.
- Clear or tamper with logs (`wevtutil cl`, shell history, auth logs) to hide activity — this is
  almost never in scope, actively harms the client's ability to do their own IR review of the
  engagement, and is a different category of action from a professional test.
- Confuse "quiet" with "authorized" — a stealthy technique on an out-of-scope host is still a
  scope violation; evasion tradecraft doesn't substitute for the authorization check.
