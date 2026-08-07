# Identity & authentication testing (WSTG-IDENT / ATHN)

The cheap parts are **script-driven**: username/account enumeration and password-policy
observation are HTTP request + response-differential logic — write a `platform_script`. The
interactive parts (driving a login form, reset flow, lockout across a real session) need a
**browser** — use `browser_flow` (see the browser skills). Default creds have dedicated tools.

## Account / username enumeration (WSTG-IDENT-04) — script

Look for **observable differences** that reveal whether an account exists, across:
- **Login** — "invalid username" vs "invalid password"; different status/redirect; **timing**
  differences (valid user → slower bcrypt path).
- **Registration** — "email already registered".
- **Password reset** — "we sent an email" vs "no such user" (many leak here).
- **Response length / headers / set-cookie presence** differences for valid vs invalid users.

Method: pick a known-valid identifier (from OSINT/recon) and a random-invalid one, send both,
diff status + length + body markers + timing. A stable, repeatable difference = enumeration
(MEDIUM; it feeds credential attacks). Keep volume low — a few requests, not a brute-force.

## Password policy & reset (WSTG-ATHN-05/09) — script + browser

- Observe the policy from the registration/reset response (min length, complexity) — weak policy
  is a LOW finding that amplifies brute-force risk.
- Password-reset token analysis: is the token in the reset link **guessable/short/sequential**,
  does it **expire**, is it **single-use**, is it tied to the user? Request two resets and
  compare tokens (needs the email you control, or `browser_flow` to drive the flow).

## Default & weak credentials (WSTG-ATHN-01) — tools

- `nuclei_scan -tags default-login` covers many products' default creds safely.
- `hydra` (creds phase) for form/basic-auth brute — but you must understand the form first
  (fields, failure marker); drive discovery with `browser_flow`, then hand hydra the shape.
- Check tech-specific defaults (Tomcat manager, Jenkins, Grafana admin/admin, .git creds).

## Authentication bypass / logic (WSTG-ATHN) — browser

Forced browsing to post-login pages, parameter-based role flags (`?admin=true`), missing
server-side checks, and alternate-channel auth all need a **session** — drive with `browser_flow`
(log in as a low-priv user, then try to reach privileged functions). See `business-logic`.

## Do not

- Brute-force logins here — enumeration is a few requests; credential attack is the next phase
  and needs approval. Lockout you trigger is noise the client will notice.
- Claim "account enumeration" from a single request — prove the difference is stable and
  valid-vs-invalid, not just server jitter.
- Test reset/change flows against real user accounts without authorisation.
