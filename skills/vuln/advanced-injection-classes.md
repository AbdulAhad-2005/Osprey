---
name: advanced-injection-classes
description: "Advanced injection classes (SSRF, SSTI, XXE, deserialization, NoSQL, open-redirect, mass-assignment): class-specific methodology beyond SQLi/XSS, often via platform_script or browser_flow."
phases: [vuln]
tags: [vuln, injection, ssrf]
---

# Advanced injection classes (SSRF, SSTI, XXE, deserialization, NoSQL, open-redirect, mass-assignment)

Beyond SQLi/XSS (see `injection-testing`), these classes need class-specific methodology. `nuclei`
templates catch the easy cases (`-tags ssrf,ssti,xxe,lfi`), but the high-impact instances are
found by understanding the sink and crafting the probe — usually a `platform_script`, sometimes
`browser_flow` to reach an authenticated sink. Test the parameters/inputs recon already found.

## SSRF (Server-Side Request Forgery) — often the highest impact

Sinks: any server-side fetcher — `url=`, `link=`, `fetch=`, `src=`, `image=`, `webhook=`,
`avatar=`, `callback=`, PDF/preview/import features, GraphQL resolvers, SSO/JWKS URL fetchers.
- **Cloud metadata = credential theft (CRITICAL):** AWS IMDS `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (IMDSv2 needs the `X-aws-ec2-metadata-token` PUT first — use a sink that lets you set headers), GCP `http://metadata.google.internal/computeMetadata/v1/` (needs `Metadata-Flavor: Google`), Azure `http://169.254.169.254/metadata/instance?api-version=...`.
- **Internal recon:** `http://127.0.0.1:<port>`, `http://localhost/admin`, cloud service meshes, k8s API `https://kubernetes.default.svc`.
- **Bypasses:** alternate IP encodings (decimal/octal/IPv6 `[::1]`), DNS rebinding, `@`-tricks,
  redirects to internal, and non-HTTP schemes (`gopher://` for smuggling, `file://`, `dict://`).
- **Blind SSRF:** use nuclei's interactsh or your own OOB listener to confirm the fetch fired.
Impact is OBSERVED once you get metadata/creds or an internal response back.

## SSTI (Server-Side Template Injection)

Where user input hits a template engine (error pages, emails, name/profile fields, reports).
- **Detect:** `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}` — a rendered `49` confirms it.
- **Fingerprint the engine** (Jinja2/Twig/Freemarker/Velocity/ERB) from which syntax evaluates,
  then escalate to file read / RCE with the engine-specific payload. SSTI → RCE is common → CRITICAL.

## XXE (XML External Entity)

Any XML sink (SOAP, SAML, `.docx`/`.svg`/`.xml` uploads, REST accepting `application/xml`).
- Inject a `DOCTYPE` with an external entity → file read (`file:///etc/passwd`), SSRF (entity to
  an internal URL), or OOB exfil (parameter entities to an attacker DTD). Blind XXE via OOB.
- Try even when JSON is default — flip `Content-Type: application/xml` and resend.

## Insecure deserialization

Serialized blobs in cookies/params/headers (Java `rO0`/`aced` base64, PHP `O:`, Python pickle,
.NET `ViewState`, Ruby Marshal). Identify the format, then use gadget chains (ysoserial-style) to
reach RCE. High impact; confirm carefully — this is detection in this phase, weaponizing is
exploitation (approval-gated).

## NoSQL injection

MongoDB-style: operator injection in JSON (`{"user":{"$ne":null},"pass":{"$ne":null}}`) or query
strings (`user[$ne]=`). Auth bypass and blind data extraction via `$regex`/`$where`.

## Open redirect

`redirect=`, `next=`, `returnUrl=`, `url=` → does it send you off-site? On its own it's LOW, but
it **chains** into OAuth token theft, SSRF filter bypass, and phishing — always note it as a chain
enabler, not just a standalone.

## Mass assignment / parameter binding

APIs that bind request JSON straight to objects: add fields the UI never sends —
`"role":"admin"`, `"isVerified":true`, `"balance":9999`, `"id":<other user>`. Capture a normal
update request with `browser_flow`, then replay with extra fields via `platform_script`. Confirm
the privileged field actually took effect.

## Do not

- Report SSRF/SSTI/XXE from a payload that *echoed* without confirming server-side effect
  (metadata retrieved, file read, entity resolved) — reflection ≠ execution.
- Weaponize deserialization / SSTI-RCE here — proving the sink is reachable and evaluates is the
  finding; gaining a shell is exploitation and needs approval.
- Hit cloud metadata on a target you're not authorised to reach that infrastructure on.
