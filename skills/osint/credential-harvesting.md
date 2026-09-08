---
name: credential-harvesting
description: "Harvest leaked credentials, emails and identities for a domain from breach intel (intelx_scan, resecurity_scan) during recon, store them as CREDENTIAL findings, and feed verified ones into exploitation."
phases: [osint]
tags: [osint, credentials, breach, exploitation]
---

# Credential Harvesting

**When:** You have a target domain/company and want the credentials, emails, and
identities already exposed in breaches and paste dumps — the highest-signal recon
there is, because a valid leaked password is a straight path to access.

## Priority of sources (highest first)

1. **Scraped live during the engagement** — creds pulled from the target itself
   (js_recon secrets, sqlmap dumps, exposed configs, `.env`/backup files). These are
   OBSERVED and outrank everything: they are real and current for *this* target.
2. **Verified-working credential-manager hits** (private Hawkeye `creds_manage` only)
   — externally verified as working. Trust them second.
3. **Breach-DB leaks** (`intelx_scan`, `resecurity_scan`) — real leaked data, but not
   verified against the live target. Treat as **leads to test**, not facts.

The platform encodes this: scraped creds are graded OBSERVED (can reach CRITICAL),
breach-DB creds are INFERRED (capped MEDIUM, tagged `verify_creds`). Sort by
`metadata.cred_priority` when choosing what to test first.

## Flow

1. **Harvest emails + identities** as part of recon: `intelx_scan` (target=domain,
   mode=phonebook) alongside `theharvester` / `web_contact_harvest`. Emails and
   subdomains land as EMAIL / SUBDOMAIN findings and build the name→email→account
   graph.
2. **Pull leaked credentials:** `intelx_scan` (mode=leaks or all — needs
   `INTELX_IDENTITY_API_KEY`) and `resecurity_scan`. Each user+password becomes a
   CREDENTIAL finding linked to its host (`exposes_credential` edge) and shown in the
   report with the actual leaked value.
3. **Deduplicate against people you already know:** cross-reference harvested emails
   with `maigret` / `holehe` results to find which accounts actually exist.
4. **Verify, then exploit:** a CREDENTIAL finding is automatically promoted to a
   `credential_bruteforce` exploit candidate. Test leaked creds against the target's
   real login surfaces (web login, SSH, VPN, mail, `hydra_attack`). Reuse and stuffing
   are common — try a leaked password across every service and sibling host.
5. **Report the outcome:** harvested creds appear in recon findings; once a credential
   is confirmed working against the live target, record that as a HIGH/CRITICAL access
   finding in the exploitation step (grade it OBSERVED — you proved it).

## Notes

- These lookups are **passive** (no packets to the target), so they are safe to run
  early and broadly, including on sister/subdomains.
- Never mask the values — the leaked credential is the finding. Show it.
- A leaked **admin** credential, or one that still works, is crown-jewel material —
  tag the host and prioritise it.
