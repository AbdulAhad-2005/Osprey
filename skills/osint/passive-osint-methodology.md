---
name: passive-osint-methodology
description: "Passive people/identity OSINT from public sources only: a recursive seed-and-dig loop starting from the target's own site, with no breach data or active exploitation."
phase: osint
tags: [osint, methodology, passive]
---

# Passive OSINT — Methodology

**Scope:** People/identity recon from **public sources only**. No breach/leak data,
no login attempts, no active exploitation. The only host you touch is the target's
**own** website (via `web_contact_harvest`).

**The loop is recursive — seed, then dig into everything you find:**

1. **SEED from the site** — `web_contact_harvest` (url=/domain=). Returns emails,
   phones, social profile links (+handles) and person names off the target's pages.
2. **WIDEN from public sources** — `theharvester` (domain=) for emails/names/hosts;
   `metagoofil` (domain=) for public documents → `exiftool_extract` for author/GPS.
3. **PIVOT every lead** (this is the point — never stop at the first hit):
   - **Name** → `email_permute` (name= + domain=) to guess addresses; `maigret` to find their handle.
   - **Email** → `holehe` (email=) for which sites hold an account (existence only).
   - **Username** → `maigret` / `sherlock` / `social_analyzer` across sites.
   - **Phone** → `phoneinfoga` (phone=, E.164) for carrier/country/footprint.
   - **Document** → `exiftool_extract` for author/software → new PERSON leads.
4. **BRAND** — `dnstwist` (domain=) for typosquat / look-alike domains.

**Grade honestly:** OSINT findings are leads. Person/social matches default to
**unverified** (name collision + username reuse are real); email/username/phone/
document are **inferred**. Never claim a person owns an account without corroboration.

**Graph pivots built automatically:** person→owns_email→email, person→uses_username→
username, username→used_on→social_account, domain→has_email→email,
document→authored_by→person. Query with `platform_graph_query`.

**Do not:** touch breach/leak databases (out of scope this build), attempt logins,
or treat a candidate email / soft social match as confirmed identity.
