# GraphQL testing (WSTG-API)

GraphQL endpoints (`/graphql`, `/api/graphql`, `/v1/graphql`) have their own class of issues.
When recon, `js_recon`, or `browser_scrape` surfaces one, run `graphql_cop_scan` (url=) — it
audits the GraphQL-specific weaknesses, output parsed into findings.

## What it checks

- **Introspection exposed** — the schema is readable (MEDIUM/INFO): maps the entire API,
  including hidden/internal mutations. Great recon, and often should be disabled in prod.
- **Field suggestions** — error messages suggest valid field names → schema recovery even with
  introspection off (LOW/INFO).
- **Query batching / aliasing** — many operations in one request → auth-brute amplification and
  DoS (MEDIUM).
- **Deep recursion** — nested queries with no depth limit → DoS (MEDIUM).
- **GET-based mutations / POST-form** — state change over GET or form-encoded → CSRF (MEDIUM).

## Follow-ups (beyond graphql-cop)

- If introspection is on, pull the schema and look for **sensitive mutations** (createUser,
  updateRole, resetPassword) — then test authorization on them with `browser_flow` (auth) or a
  crafted `platform_script` query.
- GraphQL **IDOR/authz** is common: request an object by id you shouldn't access. Test as a
  low-priv user (see `client-side-and-session`).
- **Injection** through GraphQL arguments reaches the same SQL/NoSQL sinks — feed promising
  arguments to `sqlmap` (via a saved request) or test manually.

## Do not

- Rate "introspection enabled" as HIGH by itself — it's information exposure (INFO/MEDIUM); the
  impact is what the exposed mutations let you do.
- Run batching/DoS checks aggressively against production — graphql-cop's probes are light;
  don't escalate to an actual DoS.
