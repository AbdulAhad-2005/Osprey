# Verification & severity discipline

The fastest way to make a report worthless is a wall of unverified scanner output rated
"critical." Severity is earned from evidence. The platform enforces this — understand it so you
work with it, not against it.

## Evidence grade caps severity (platform clamp)

Every finding has an `evidence_grade`, and it caps the `claim_severity` you can assign:

| Grade | Meaning | Max severity |
|-------|---------|--------------|
| `observed` | live response proves the condition (scanner match, fetched file, firing payload) | CRITICAL |
| `inferred` | soft signal — version banner, reflected-but-unverified, name/DNS match | MEDIUM |
| `unverified` | noise, unparsed, passive guess | INFO |

So a CVE "guessed" from a version banner alone is INFERRED → capped at MEDIUM, no matter how bad
the CVE is. To claim HIGH/CRITICAL you must **observe** it: reach the vulnerable endpoint, get
the disclosing response, fire the payload. That's the whole game.

## What counts as observed vs inferred

- **Observed:** sqlmap confirmed injection; dalfox verified (type V) XSS; nuclei matched an
  actual exposure you then fetched; wpscan found a file that returns real content.
- **Inferred:** nuclei/wpscan flagged a version in an affected range (but you didn't confirm the
  exploit path); a reflected XSS lead (type R) not yet verified; a CVE implied by a banner.
- **Unverified:** raw scanner text with no structured match; a template that "could" apply.

## Turning inferred into observed

1. **Pin the version** — confirm the *running* version is actually in the vulnerable range, not
   just "≤ X" from a banner.
2. **Reach the sink** — confirm the vulnerable endpoint/parameter is present and reachable
   (auth, WAF, path may block it).
3. **Get a response** — fetch the file, trigger the error, fire the payload. Record the request
   and the response as evidence.
4. Only then raise the grade to `observed` and the severity to what the impact warrants.

## Writing the finding

- Title = the specific issue (CVE / class + location), not the tool name.
- Evidence = the reproducing request/response or the scanner's matched-at line.
- Severity = impact **given confirmed exploitability**, clamped by grade. Don't inflate.
- Note false-positive risk explicitly when you couldn't verify ("flagged by version; exploit
  path unconfirmed").

## Do not

- Copy the scanner's severity verbatim onto an unverified match.
- Claim impact you didn't observe. "Vulnerable version present" ≠ "exploitable."
- Bury real criticals under info-level fingerprint noise — rank by verified impact.
