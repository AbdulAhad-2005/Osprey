# Third-Party Notices

This file records third-party content reused or adapted anywhere in this repository, per
license terms that require attribution.

## Skill library (`skills/`)

Some files under `skills/` adapt techniques, structure, or wording from open-source security
skill libraries. Adaptation means rewritten/restructured for this platform's own tool set,
conventions (`blast_radius`, `evidence_grade`, `platform_shell`/`platform_script`), and
frontmatter schema — not verbatim copying — but the source project and license are recorded
here per each project's attribution requirement.

| Source | License | Used for |
|---|---|---|
| [Strix](https://github.com/usestrix/strix) (`strix/skills/`) | Apache-2.0 | Domain-skill structure and technique content — `active-directory` phase-overview draws on `skills/technologies/active_directory.md`. |
| [Anthropic Skills](https://github.com/anthropics/skills) (`skills/`) | Apache-2.0 | Cross-checked for technique coverage (e.g. specific AD CS ESC variants, DCSync/Kerberoasting/lateral-movement details) against the domain skills above. |
| [Transilience AI — communitytools](https://github.com/transilience-ai) (`skills/`) | MIT | Cross-checked `system/reference/` for foothold/lateral-movement patterns. |

Per-file attribution: any `skills/*.md` file with content adapted from one of the above carries
an HTML comment at the top of its body naming the source, e.g.:
```html
<!-- Adapted from strix/skills/technologies/active_directory.md (Apache-2.0). -->
```

## Command-builder / error-handling recipes (`mcp-servers/`)

`mcp-servers/README.md` references third-party attribution for reused command-builder recipes
and error-handling logic predating this file's creation. That attribution should be backfilled
here by whoever introduced the reused logic — not fabricated after the fact.
