# Web application methodology (optional skills overlay)

Focus on HTTP(S) apps once hosts/URLs exist in memory. Not a mandatory stage —
load via `platform_context` when useful, or just follow gaps.

## Goals

- Map interesting apps (login, APIs, admin, upload, SSO)
- Light fingerprinting; prefer high-value hosts from the attack-surface tree

## Operate

1. `platform_context()` — read inferred focus + gaps
2. `platform_exec` / `platform_shell` for the next useful check
3. Re-read context; stay in scope
