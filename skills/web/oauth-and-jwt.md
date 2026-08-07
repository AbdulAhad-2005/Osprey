# OAuth / OIDC & JWT testing (WSTG-ATHN / SESS)

Token and SSO failures are the account-takeover class — treat every redirect, client id, key,
and claim as an authorization boundary, not plumbing. Discovery is a `platform_script`/
`well_known_probe`; driving the login is `browser_flow`; forging/replaying tokens is a
`platform_script`.

## Discovery

Fetch the config + keys (`platform_script` curl or `well_known_probe`):
```
/.well-known/openid-configuration   /.well-known/oauth-authorization-server
/jwks.json                          /oauth2/.well-known/openid-configuration
```
Extract `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`,
`code_challenge_methods_supported` (PKCE), `grant_types_supported`. Note `/authorize`, `/token`,
`/userinfo`, `/callback`, `/logout`, refresh + introspection endpoints.

## OAuth 2.0 / OIDC flaws

- **redirect_uri manipulation** — the highest-yield bug. Try appended paths, `@evil.com`,
  `evil.com#`, `?`/`;` tricks, wildcard/subdomain abuse, path traversal, open-redirect chains on
  a whitelisted host. A redirect you control leaks the `code`/token → account takeover.
- **state / nonce** — missing or predictable → login CSRF / code injection. Confirm `state` is
  bound to the session and validated.
- **PKCE downgrade** — server accepts `plain` or a missing `code_verifier` when it should require
  S256. Test by dropping/altering the verifier at `/token`.
- **Implicit / token leakage** — tokens in the URL fragment leak via Referer, history, logs.
- **Client confusion / mix-up** — a code/token issued for client A redeemed at client B.
- **Scope / consent** — request extra scopes; see if consent is skipped or scopes are honored
  server-side.

Drive the flow with `browser_flow` (log in, capture the `/authorize`→`/callback` requests), then
replay the token exchange with tampered `redirect_uri`/`code_verifier` via `platform_script`.

## JWT flaws

Decode the token (header + claims) first — `js_recon` often finds it, or grab it from the
`browser_flow` session cookies/headers. Then test:

- **`alg` confusion** — RS256→HS256: re-sign with the public key (from `jwks.json`) as the HMAC
  secret when the server doesn't pin the algorithm. **`alg:none`** — set none and strip the
  signature.
- **Header injection** — `kid` path traversal (`../../dev/null`, a known file), SQL/command
  injection in the key lookup; **`jku`/`x5u`** pointing to an attacker-hosted JWKS (SSRF + key
  trust) if not whitelisted; inline **`jwk`** the server trusts over its configured key.
- **Claim tampering** — flip `sub`/`role`/`scope`/`admin`, change `aud`/`iss` for cross-service
  reuse, ignore `exp`/`nbf`. Only works if signature validation is weak/bypassed — chain with the
  alg/header bugs above.
- **Token confusion** — use an ID token where an access token is required (server checks
  signature but not `typ`/`aud`).
- **Weak secret** — HS256 with a guessable secret → crack offline (`hashcat` mode 16500), then
  forge any token.

## Follow-ups

- Forged/tampered token that the server accepts → **CRITICAL** auth bypass / account takeover
  (OBSERVED once you replay it and reach a protected resource with `platform_script`).
- `jku`/`x5u`/`kid`-remote-fetch → also test as **SSRF** (see advanced-injection).
- Post-logout token still valid, refresh token reuse → session-management findings.

## Do not

- Claim takeover from a decoded token alone — you must **forge/replay** and confirm the server
  accepts it against a protected endpoint.
- Test against real user accounts beyond the authorised test accounts.
- Crack a captured token's secret and use it without confirming scope allows credential attacks.
