# Email & People Harvest

**When:** You have a domain/company and want its public email + people surface.

**Default:** `theharvester` (domain=) — keyless search-engine/CT/OSINT harvest of
emails, names, subdomains and hosts. Seed the site first with `web_contact_harvest`.

**Pivot rules:**
- **Name found, no email** → `email_permute` (name= + domain=) → candidate addresses
  (unverified; MX-checked) → confirm each with `holehe`.
- **Email found** → `holehe` (email=) → which sites have an account (existence only,
  **no** passwords / breach data).
- **Thin results** → widen `theharvester` sources: `sources=all` (keyed engines warn +
  skip without a key), or crawl deeper with `web_contact_harvest` (depth=1, max_pages=40).
- **Person → their handle** → `maigret` (username=) once you infer a handle from the
  email local-part or name.

**Params:** `theharvester` domain=; `holehe` email=; `email_permute` name= + domain=.
Any extra flags via `additional_args`.

**Grade:** harvested emails/names → inferred; permutation candidates → unverified.

**Do not:** use breach/leak lookups (out of scope), or send mail / attempt SMTP auth.
