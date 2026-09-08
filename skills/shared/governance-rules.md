---
name: governance-rules
description: Scope and authorization rules, plus the canonical definitions of blast_radius, destructive_actions_allowed, and allow_exploitation that every exploit/post-exploitation skill assumes. Use when running any GATED catalog tool or any platform_shell/platform_script command with real-world effect on the target.
phases: [shared]
tags: [governance, scope, roe]
---

# Governance Rules

## Scope

- Only test `RulesOfEngagement.scope.in_scope_targets` (CIDR ranges, domains, or IPs) — never
  `out_of_scope` entries, even one reached as a live pivot mid-engagement.
- A discovered asset (new subdomain, internal host reached via lateral movement, a sister domain)
  is not automatically in scope just because you can reach it — check it against
  `in_scope_targets`/`out_of_scope` before testing, whether it's the seed target or three hops
  into a post-exploitation chain.
- "Authorization unclear" concretely means: the target isn't in `in_scope_targets`, is on
  `out_of_scope`, or the engagement's `description` doesn't plausibly cover what you're about to
  do (scope says "web app", you've pivoted into internal AD — stop and flag it, don't assume AD
  testing was implied by a web-app engagement). Record the ambiguity rather than proceeding on a
  guess.

## blast_radius / destructive_actions_allowed / allow_exploitation — what's actually enforced

Two execution paths in this platform have two different enforcement realities. Know which one a
technique goes through before assuming a gate protects it — this section is the canonical
definition every `exploit/*`, `active-directory/*`, and future post-exploitation skill assumes.

**Catalog tools** (`platform_exec`, any tool with a dedicated MCP wrapper — nmap, sqlmap,
metasploit_run, hydra, etc.) are tagged `SAFE` or `GATED` (`ToolSafetyLevel`). A `GATED` call is
enforced server-side (`tool_execution.py`) before it runs:
- `RulesOfEngagement.allow_exploitation` must be `True` on the engagement, or the call 403s.
- If you declare `blast_radius="destructive"` on the call, `destructive_actions_allowed` must
  also be `True`, or it 403s. `blast_radius="poc"` (the default) skips that second check — it's
  for non-destructive proof (read one file, confirm a login, get a shell banner).
- Default to `blast_radius="poc"` unless the engagement has explicitly authorized more and the
  goal genuinely requires it — declare it honestly, it isn't a formality to route around.

**`platform_shell` / `platform_script`** — the primitive every AD/credential-access/lateral-
movement/persistence skill uses today, since none of those tools have a dedicated MCP wrapper —
have **no `blast_radius` concept and no ROE enforcement at all**. They run whatever command you
give them; the only gate is a binary allowlist when `enable_unrestricted_shell` is off (it's on
by default, so in practice there usually isn't even that). A skill describing a DCSync, golden
ticket, or password-reset command as "destructive-tier" is naming an **operator judgment call**,
not a system-enforced gate — there is no 403 backstopping a bad decision on this path. This
platform's `RulesOfEngagement` defaults permissive (`allow_exploitation`/
`destructive_actions_allowed` both default `True`) because it's built for a single authorized
operator testing their own declared scope, not a multi-tenant service brokering third-party
access — which is exactly why the judgment has to be real: the responsibility sits with the call
you make, not with a check that will stop you.

`allow_post_exploitation` exists on `RulesOfEngagement` but is not read by any enforcement code
today — treat it as documented intent, not a gate you can rely on.

## Do not

- Run destructive exploits, credential dumps, or post-exploitation moves against anything not
  explicitly in scope — regardless of which execution path (catalog tool or shell/script)
  happens to enforce what.
- Treat "the command didn't 403" as proof it was authorized — `platform_shell`/`platform_script`
  don't check authorization at all; that's on you before you send the command, not after.
- Persist (golden tickets, backdoor accounts, added ACEs, scheduled tasks) beyond what the
  engagement scope explicitly authorizes, even though nothing will technically stop you from
  trying.
