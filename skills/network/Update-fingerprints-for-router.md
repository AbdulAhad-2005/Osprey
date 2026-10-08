---
name: osprey-auto-fingerprint
description: Automatically extend Osprey's network-device fingerprint database when web fingerprinting encounters a reproducible device signature that is not represented by known signatures.
---

# Osprey Auto-Fingerprint Skill

## Goal

When Osprey's web/device fingerprinter encounters a response that does not match any known signature, create a validated fingerprint candidate and, when sufficiently distinctive, add it to the existing fingerprint registry with a regression test.

**Do not blindly promote every unknown page.** Unknown responses may be custom pages, proxies, WAFs, load balancers, generic web servers, modified vendor interfaces, or unsupported products.

## Workflow

### 1. Collect passive evidence

Use the existing `web_fingerprint` pipeline and collect available evidence:

- final URL and redirects
- HTTP status
- response headers and `Server`
- `Content-Type`
- page title
- response body/text
- distinctive management paths
- JavaScript/CSS asset paths
- favicon hash when available
- TLS metadata when available

Use GET/passive requests only. Do not authenticate, submit forms, brute-force credentials, or perform state-changing actions.

### 2. Match existing signatures first

Run the collected evidence through the existing fingerprint registry.

If a known signature matches with sufficient confidence, return that result and **do not modify the registry**.

### 3. Identify an unknown candidate

Only create a candidate when there is stable, distinctive evidence. Prefer:

- unique vendor/product strings
- product-specific HTML markers
- product-specific management paths
- product-specific JavaScript/CSS paths
- distinctive headers
- stable favicon hashes
- distinctive redirects

Do not promote generic values such as `nginx`, `Apache`, `Microsoft-IIS`, `Login`, `Username`, `Password`, or generic error pages.

### 4. Build the candidate

Use the same signature structure as the existing fingerprint database. At minimum:

```text
vendor
product
signatures
confidence/evidence rules
```

If vendor/product cannot be established, classify the result as `unknown-device` and retain the evidence as a candidate rather than inventing an identity.

### 5. Generate stable signatures

Prefer multiple independent indicators.

A strong candidate normally contains either:

- one strong product/vendor marker, or
- two or more independent medium-strength markers.

Example:

```python
{
    "vendor": "ExampleCorp",
    "product": "Secure Gateway",
    "signatures": [
        "examplecorp secure gateway",
        "/static/example-gateway.js",
    ],
}
```

### 6. Collision-check before registration

Before adding a candidate:

1. compare proposed signatures with all existing signatures;
2. reject duplicate signatures;
3. detect overly broad substrings;
4. verify the candidate does not incorrectly match another vendor/product;
5. preserve existing higher-confidence signatures.

Never weaken an existing fingerprint to make the new one fit.

### 7. Register the fingerprint

Add validated signatures to Osprey's existing fingerprint registry. **Do not create a second fingerprint database.**

The new fingerprint must be consumed by the same engine used by normal `web_fingerprint` detection.

### 8. Create a regression test

Every promoted fingerprint must have a regression test using sanitized representative evidence.

Assert both:

```text
representative device response -> expected vendor/product
unrelated generic response     -> no match
```

### 9. Preserve provenance safely

Where the repository supports provenance, record:

- detection source
- detection time
- evidence used
- confidence
- whether automatically generated or manually confirmed

Never store credentials, cookies, authorization headers, tokens, or other secrets as fingerprint evidence.

### 10. Validate

After registration:

1. run the new regression test;
2. run the existing fingerprint tests;
3. run collision/false-positive tests if available;
4. verify existing vendor fingerprints still resolve correctly.

If validation fails, do not promote the candidate.

## Promotion policy

### HIGH confidence

Automatically register only when there are at least two independent strong indicators, for example:

```text
vendor/product marker + product-specific management path
```

### MEDIUM confidence

Create a candidate and require validation before permanent registration.

### LOW confidence

Keep as an unidentified candidate. Do not modify the known-signature registry.

## Osprey integration

Follow Osprey's normal typed-tool architecture:

```text
mcp-servers/network/tools/web_fingerprint.py
        |
        v
fingerprint engine
        |
        +-- known signature -> normal typed observation
        |
        +-- unknown signature
                    |
                    v
             candidate builder
                    |
                    v
             collision checker
                    |
                    v
             signature registry
                    |
                    v
             regression test
```

The backend `web_fingerprint` tool registration should remain the normal typed-tool registration. This skill extends the fingerprint data/learning workflow; it does not create a second scanner or registry.

## Example

Given:

```text
GET /login
Title: Example Secure Gateway
Body: ExampleCorp Secure Gateway
Script: /static/example-gateway.js
```

and no existing match, derive a candidate such as:

```text
vendor: ExampleCorp
product: Secure Gateway
signatures:
- "ExampleCorp Secure Gateway"
- "/static/example-gateway.js"
```

Then collision-check, validate, register, add a regression test, and rerun the fingerprint suite.

## Never

Do not execute discovered exploit code, authenticate, brute-force credentials, submit login forms, modify the target, use generic server headers as vendor fingerprints, automatically register a single weak string, overwrite existing signatures without collision review, or store secrets/cookies as evidence.

## Expected implementation deliverable

When invoked for implementation work, produce:

1. updated fingerprint registry/signature data;
2. candidate/provenance handling where supported;
3. regression tests;
4. required parser/typed-observation updates;
5. a concise report of the newly learned fingerprint and evidence used.
