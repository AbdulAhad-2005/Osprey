# Username Pivot

**When:** You have a username / handle (from a social link, email local-part, or
document author) and want their footprint across platforms.

**Default:** `maigret` (username=) — deep search across 3000+ sites, extracts profile
data and linked accounts.

**Pivot rules:**
- **Speed over depth** → `sherlock` (username=) for a fast 400-site sweep first.
- **Confidence filtering** → `social_analyzer` (username=, filter_level=good) to cut
  false positives.
- **New handle discovered on a profile** → recurse: run `maigret` on the new handle.
- **Handle looks like a name** → `email_permute` (name= + domain=) then `holehe`.

**Params:** `username`. Tune `timeout` / `top_sites` (maigret) for speed. Extra flags
via `additional_args`.

**Grade:** social matches default to **unverified** — username reuse across people is
common. Corroborate (matching avatar, bio, linked email) before asserting identity.

**Do not:** log in, message accounts, or treat a single-site hit as confirmed identity.
