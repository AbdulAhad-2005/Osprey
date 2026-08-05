# Vulnerability Analysis Phase

Goal: turn the attack surface recon mapped into **confirmed, severity-rated findings**.
Recon found *what exists* (hosts, services, tech, URLs, parameters, secrets); this phase
finds *what's wrong* with it — and proves it, honestly.

This is a distinct phase, not a blind scanner sweep. Scan what the evidence points at.

**Instincts (order of concerns — not mandatory stages):**
1. **Scan live web hosts with `nuclei_scan`** — the recon→vuln workhorse. Once tech is
   fingerprinted, nuclei checks version/CVE/misconfig templates. Filter by
   `severity=critical,high` first for signal, widen later.
2. **Server misconfig** — `nikto_scan` on web hosts for dangerous files, default pages,
   missing headers, exposed backups.
3. **CMS** — WordPress detected? `wpscan_analyze` enumerates core/plugin/theme CVEs. This
   is high-yield: 30%+ of the web is WordPress and plugins are where it rots.
4. **Injection testing on recon's parameters** — every `injection_point_candidate` (from
   `arjun_scan`/param mining) and every interesting parameter is a lead: `sqlmap_scan` for
   SQLi, `dalfox_xss_scan` for XSS. Test what recon found, not random inputs.
5. **Signature scan** — `jaeles_vulnerability_scan` complements nuclei with a different
   signature set on high-value apps.

**What feeds this phase (from recon):** `technology` findings (→ targeted templates),
`injection_point_candidate` tags (→ sqlmap/dalfox), `interesting_path`/`js-secret`/
`cloud-asset` leads (→ verify), live URLs and open services.

**Prioritise by exposure × value:** crown jewels and internet-facing app hosts first.
Use `platform_context` coverage gaps + crown jewels rather than scanning every asset equally.

**Severity is earned, not claimed:** see `verification-and-severity`. A scanner match is a
lead until you understand it; the platform clamps severity to evidence grade.

**Exploitation is the NEXT phase and needs explicit approval.** This phase *confirms and
rates* vulnerabilities. Running sqlmap to prove an injection exists is analysis; dumping the
database is exploitation — stop at proof unless the engagement authorises more.

**Do not:**
- Fire every scanner at every asset — waste, noise, and WAF bans. Scan by evidence.
- Escalate to CRITICAL from a version banner alone — that's INFERRED until a live check.
- Run intrusive/GATED tools (sqlmap, aggressive nuclei) outside agreed scope.
