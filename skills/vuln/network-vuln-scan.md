---
name: network-vuln-scan
description: "Network-side vulnerability scanning via nmap NSE vuln/vulners against already-open ports and services; the network counterpart to nuclei."
phase: vuln
tags: [vuln, network, nmap]
---

# Network vulnerability scan — nmap NSE `vuln`/`vulners` categories

`nmap_custom_scan` with `--script "vuln,vulners"` is the network-side counterpart to nuclei:
it checks whatever ports/services recon already established, not a fixed protocol list. nmap
selects the applicable checks itself from its own script library based on what's actually
open — SSH, SMB, RDP, FTP, SMTP, NFS, HTTP, and anything else nmap has script coverage for.
There is no per-service catalog to maintain or expand here; new nmap versions bring new
coverage automatically.

## When and how

- **After service scan established ports/services.** This depends on prior recon
  (`nmap_service_scan`/`nmap_syn_scan`) having already mapped what's open — running this blind
  against an unscanned host wastes the scan window on closed ports.
- Call `nmap_custom_scan` with `additional_args` set to `-Pn -sV --script "vuln,vulners" -p <ports>`
  against the host, using the port list recon already found. `-Pn` is required even for a plain
  connect scan in this platform's execution environment (no raw-socket capability) — omit it and
  host discovery silently fails before the script scan even starts.
- Narrow `-p` to the ports recon found open. Scanning all 65535 ports with the full script set is
  slow and mostly wasted — you already know what's open.
- One invocation covers both generic CVE-banner matching (`vulners`) and protocol-specific
  active checks (`vuln` category — e.g. `smb-vuln-ms17-010`, `ftp-vuln-cve2010-4221`,
  `http-vuln-*`, `rdp-vuln-*`) in a single pass.

## Reading results

- Two evidence grades come out of the same scan, by design:
  - **OBSERVED** findings are from scripts that actively tested the condition (the `vuln`
    category — e.g. an SMB script that confirmed MS17-010 is exploitable). These can carry
    HIGH/CRITICAL.
  - **INFERRED** findings are from `vulners`' CVE-banner matching (a version string implies a
    CVE might apply — not independently verified). These are clamped to at most MEDIUM
    `claim_severity` regardless of the underlying CVE's CVSS score; use `metadata.cvss_score`
    for the real severity signal when sorting/prioritizing, not `claim_severity`.
- `metadata.exploit_available_hint` marks vulners entries nmap itself flagged with `*EXPLOIT*`
  (a known public PoC exists per vulners.com). Prioritize these.
- Some script output doesn't fit either shape (unusual/new scripts) — those still show up as
  findings (never silently dropped), sometimes structured by the platform's dynamic parser,
  sometimes as a raw captured block. Read the raw block yourself if it's high-signal-looking but
  came through unstructured.

## Follow-ups by match

- **OBSERVED vulnerability with `exploit_available_hint`** → high-confidence next step:
  cross-reference with `searchsploit_lookup` for a concrete PoC/module before considering
  further action (needs approval for anything beyond lookup).
- **INFERRED CVE match** → banner-based, not confirmed. Don't report as CONFIRMED severity;
  corroborate with a live, protocol-specific check if one exists before escalating.
- **Multiple hosts** → use `platform_fanout_assets` with `nmap_custom_scan` across the host list
  recon discovered rather than looping calls yourself — it's already bounded-concurrency and
  dry-run-gated.

## Do not

- Hand-pick a short list of "important" services/scripts to check — the whole point of
  `--script vuln,vulners` is that nmap already covers everything it knows about; narrowing to a
  guessed subset silently drops coverage.
- Treat an INFERRED vulners hit as proof of exploitability — it's a lead, not a confirmed finding.
- Run this before service/version detection has run — without `-sV` data, `vulners`' CPE matching
  has nothing to match against and returns nothing useful.
