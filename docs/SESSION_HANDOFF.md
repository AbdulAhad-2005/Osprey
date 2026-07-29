# Pentest Platform Session Handoff

**Date:** 2026-07-28
**Current State:** Platform v3.5+ with subdomain-profile completeness tracking, open-gaps dedup, service enumeration gaps, and context-bloat reduction for OpenCode
**Next Session Focus:** Deepen service enumeration (full port scans), OS detection fix, and pilot on morth.gov.in

---

## Executive Summary

The pentest-platform has been enhanced over this session with three major capabilities:

1. **Subdomain Profile Completeness Tracking** — every host/subdomain must have IP resolved, tech fingerprinted, WAF checked, and OS-detection attempted (or marked incomplete in `platform_finalize_check`)
2. **Open Gaps Delta-Aware Deduplication** — OPEN GAPS section no longer repeats identical text every tool call; compresses to one-liners while content signature is stable
3. **Context-Bloat Reduction for OpenCode** — per-tool digest (`digest_tool_output`) + reduced inline stdout when digest exists, preventing 50k-char GAU dumps from filling operator context every call

A comprehensive report was generated for civilaviation.gov.in (871 lines, 824+ findings), demonstrating real depth: Akamai/CloudFront defense analysis, Drupal 10 CMS profiling, shared-host service enumeration (ProFTPD/Dovecot/Postfix/BIND), and honest severity calibration. **Analysis found it good but with gaps:** full port scans (1–65535) timed out and weren't retried as background jobs; 533 unexplored assets need individual spot-checks before dismissal; OS detection blocked by unprivileged environment.

---

## Platform Architecture & Recent Changes

### Three-Plane Architecture

- **Execution Plane:** Tools run natively (nmap, subfinder, custom scripts)
- **Control Plane:** Platform orchestrator (job start/poll, cache, recovery)
- **Cognition Plane:** OpenCode operator (reads context/findings, decides next probe)

### Core Improvements This Session

#### 1. Subdomain Profile Completeness (`open_loops.py` + `finalize_readiness.py`)

**Files modified:**

- `backend/src/pentest_platform/services/open_loops.py`

  - Added `find_incomplete_subdomain_profiles()` function tracking IP/tech/WAF/OS per subdomain
  - Added host-keyed service-gap loops (`unscanned_hosts`, `hosts_ports_without_services`)
  - Updated `strongly_recommend_continue` logic to fold in service gaps + incomplete profiles
  - Returns `service_gap_count` and `incomplete_profile_count` fields
- `backend/src/pentest_platform/services/finalize_readiness.py`

  - Wired `find_incomplete_subdomain_profiles()` into `platform_finalize_check` response
  - Updated `look_back` dict with `incomplete_profiles` list + count
  - Enhanced `strong_continue_reasons` banner to show full breakdown: "X unlinked, Y unexplored, Z missing port/service scan, W missing ip/tech/waf/os profile"

**What "complete" means:**

- IP: resolves_to edge exists to an IP node
- Tech: TECHNOLOGY finding exists
- WAF: waf/no_waf tags exist OR wafw00f_scan/shodan_host_info coverage recorded
- OS: os tags exist OR nmap_custom_scan (with -O/-A) / shodan_host_info coverage recorded
  - **Special:** OS only requires attempted, not guaranteed (many services never reveal it even when correctly probed)
  - **Critical Gap:** nmap -O fails in kali-tools container (unprivileged user, no raw-socket capability) — needs `setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap` in Dockerfile to work

**Verified live:**

- Single bare subdomain → `incomplete_profile_count=1`, `subdomain_profile_incomplete` loop appears
- Five bare subdomains → `strongly_recommend_continue` fires with breakdown (5 unlinked, 5 unexplored, 5 missing service scan, 5 incomplete profile)

---

#### 2. Open Gaps Delta-Aware Deduplication (`open_loops.py` + `finalize_rules.yaml`)

**Problem solved:** Session with 20+ tool calls + 50k-char GAU dump was truncating mid-response in OpenCode because OPEN GAPS section was inlined and repeated verbatim every call, bloating context by ~3k chars per tool.

**Solution:**

- `open_loops.py` now computes a signature of the gaps text
- If signature hasn't changed since last show, compress to one-liner: "OPEN GAPS (20 items, unchanged since last call)"
- If signature changed or refresh_every cap reached, show full detail
- Dedup config in `config/finalize_rules.yaml`:
  ```yaml
  open_gaps_dedup_enabled: true
  open_gaps_refresh_every: 5  # show full detail every 5 calls even if unchanged
  ```

**Verified:** Large session with repeated gap types → OPEN GAPS compresses after first full display, resurfaces in detail on any content change or every 5 calls

---

#### 3. OS Detection Parser + Context-Bloat Reduction

**`backend/src/pentest_platform/services/parsers/recon_network.py`:**

- Added module-level regex for OS detection:
  ```python
  _OS_DETAILS_RE = re.compile(r"^OS details:\s*(.+)$")
  _OS_AGGRESSIVE_RE = re.compile(r"^Aggressive OS guesses:\s*(.+)$")
  _OS_RUNNING_RE = re.compile(r"^Running:\s*(.+)$")
  _OS_NO_MATCH_RE = re.compile(r"^No exact OS matches for host")
  ```
- `parse_nmap_text()` now extracts OS and emits OBSERVATION findings with confidence tiers:
  - OBSERVED (grade) — from "OS details:" (nmap -O with root privileges)
  - INFERRED (grade) — from "Running:" / "Aggressive OS guesses:" (best-effort heuristics)
  - UNVERIFIED (grade) — from "No exact OS match" (probe ran, no result)
- `parse_shodan_host_info()` extracts and emits OS field from Shodan as OBSERVATION finding with tags ["os", "os_detected", "shodan"]

**`backend/src/pentest_platform/services/tool_execution.py`:**

- Added `_attach_digest()` function that computes per-tool digest server-side and attaches to HTTP response's `hybrid.digest` field
- This digest is available to **all** consumers (OpenCode MCP path + built-in agent path), not just one
- New function added after every tool execution

**`backend/src/pentest_platform/services/parsers/recon_network.py` (URL-list parser):**

- Added `extract_url_list_digest()` for gau_discovery/waybackurls_discovery/hakrawler_crawl
  - Extracts unique URLs from large dumps (these tools output 10k+ URLs with high repetition)
  - Surfaces security-interesting ones (/api, /admin, /wp-, /.git, .php, .sql, .zip, etc.) instead of arbitrary first-N
  - Digest format: "2003 unique URL(s) found — interesting: [sample URLs] (+1991 more)"
- Added `parse_gau()`, `parse_waybackurls()`, `parse_hakrawler()` — structured URL findings (capped at 300 per tool to avoid bloat)
- Registered parsers/digesters for all three tools

**Real bug fixed:** Initial interesting-URL marker list included bare `"?"` which matched almost every URL with a query string (most gau/wayback output), drowning out genuinely distinctive paths. Removed it; re-verified with synthetic 2003-URL test — digest now correctly surfaces 3 planted interesting URLs instead of being crowded out.

**`platform-mcp/server.py` (`_format_exec_result`):**

- When digest exists, reduce inline stdout cap from 12000/6000+3000 to 2500/1800+700 chars
- Show digest prominently as `**PARSED SUMMARY:**` section right after command
- Tools without registered digest keep original generous cap (raw stdout is their only signal)

**Verified live:** Real nmap_service_scan against scanme.nmap.org → `hybrid.digest` populated end-to-end ("scanme.nmap.org: 2 open port(s): 22/tcp ssh OpenSSH 6.6.1p1...")

---

## AGENTS.md Recent Updates

**Item 8 (mandatory subdomain profiling):** Completely rewritten to anchor completeness requirement to now-tracked mechanism:

```
Every subdomain/host must be profiled to its full extent: IP resolved, tech fingerprinted,
WAF checked, service enumeration on every open port, and an OS-detection attempt
(nmap_custom_scan with -O/-A, or shodan_host_info). Unless you know all of the above
for every domain and subdomain, you can never stop. This is not just an instruction —
memory tracks it: platform_finalize_check's incomplete_profiles and every tool response's
OPEN GAPS both list exactly which subdomains are still missing which field.
```

**Item 9:** Updated to emphasize never-finalize-unless-user-stops discipline

**"Honesty on severity" section:** Updated to treat incomplete profiles as a real reason to keep going

---

## civilaviation.gov.in Report Analysis

### What Went Well

**Real pivots, not surface scans:**

- Discovered `civilaviationglobal.com` shares IP (149.255.62.131) with unrelated third-party sites
- Fully enumerated that shared host's service stack:
  - Port 21: ProFTPD (TLS)
  - Port 53: Plesk Onyx BIND (DNS, version hidden)
  - Port 80: nginx
  - Port 110: Dovecot pop3d (TLS, SASL methods: PLAIN/LOGIN/DIGEST-MD5/CRAM-MD5)
  - Port 465: Postfix smtpd (TLS, AUTH: DIGEST-MD5/CRAM-MD5/PLAIN/LOGIN)
- This is exactly the "every asset can still surface something" behavior the platform's trying to instill

**Honest scope discipline:**

- Correctly identified civilaviationglobal.com as unrelated (different registrar, no gov.in certs)
- Didn't inflate its severity relative to actual target
- Recognized brand-impersonation risk on parked sister domains but downgraded real-world impact

**Limitations clearly stated (Section 14.2):**

- Tool install gaps (wappalyzer/whatweb not in Kali)
- Shodan API limits
- OS detection blocked by unprivileged environment
- NIC DNS locked down
- Roundcube version not discernible externally

**Finals metrics:**

- 871 lines, 69KB
- 824+ findings (351 observed, 522 inferred, 38 unverified)
- 8 crown jewels identified with scoring
- Complete methodology section
- Full external links analysis (77 links)
- GAU historical URL analysis (696 URLs)

---

### Where It's Incomplete (Per AGENTS.md "Mandatory Depth")

**1. Full port scans (1–65535) failed and weren't retried**

- Report states: "Full 65535 port scans attempted on civilaviation.com, civilaviation.net, civilaviationglobal.com via nmap_custom_scan — all timed out (120s default). Chunked retries also failed."
- **AGENTS.md rule:** "use `platform_job_start` for long scans so they run in background while other work continues"
- **Gap:** Should have been moved to background jobs with 600s+ timeout instead of abandoned
- **Risk:** If services exist on ports >10000 on sister domains, they'd be missed
- **Recommendation:** Retry with `nmap_custom_scan` flags="-sV -p-" timeout=600 on 86.105.245.69, 52.40.42.113, 44.232.173.249, 149.255.62.131 using `platform_job_start`

**2. OS detection never fired**

- nmap -O fails because kali-tools container runs as unprivileged `mcpuser` without raw-socket capability applied
- **Fix required:** Add `setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap` to kali-tools Dockerfile
- **Why it matters:** The completeness-tracking I added expects OS attempts — currently it always reports "os missing" because the attempt always fails silently

**3. 533 unexplored assets categorized but not individually verified**

- Report dismisses them as "mostly GAU YouTube URLs, .well-known, parameter noise"
- **AGENTS.md rule:** "do NOT explain it away in bulk... without actually checking a real sample of them individually first"
- **Recommendation:** Pick 50 of the 533, httpx-probe them, report which are 200 OK/404/timeout, optionally tech-detect the live ones

**4. Severity calibration edge cases**

- `/rebuild.php → 200` and `/user/login → 200` labeled MEDIUM without proving actual effect
- `/user/login` on a public gov portal is expected behavior, not inherently risky (no enumeration was found; login attempts ARE blocked)
- `/rebuild.php` accessibility doesn't prove unauth rebuild is possible (Drupal may require session)
- **Better approach:** Verify if hitting /rebuild.php unauthenticated actually triggers a rebuild or just serves a page

---

## Known Platform Limitations & Fixes Needed

| Issue                                | Status                               | Fix                                                                            |
| ------------------------------------ | ------------------------------------ | ------------------------------------------------------------------------------ |
| nmap -O requires root                | Confirmed broken                     | Add`setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap` to Dockerfile        |
| Full port scans timeout at 120s      | Not a platform bug; execution choice | Use`platform_job_start` with timeout=600 for next engagement                 |
| GAU/wayback/hakrawler huge raw dumps | **FIXED**                      | Per-tool digest + reduced inline stdout when digest exists                     |
| OPEN GAPS repeats every call         | **FIXED**                      | Delta-aware dedup compresses to one-liner while signature unchanged            |
| Subdomain incompleteness invisible   | **FIXED**                      | `incomplete_profiles` field + host-keyed service gaps now tracked            |
| OS detection capability missing      | **FIXED** (parser)             | Parser works; execution blocked by unprivileged environment (Dockerfile issue) |

---

## Next Engagement Roadmap

### Immediate (morth.gov.in pilot)

1. **Run civilaviation.gov.in round 2 with full port scans:**

   - `nmap_custom_scan` flags="-sV -p-" timeout=600 on all 4 sister domain IPs
   - Use `platform_job_start` so work continues in parallel
   - Report any non-standard ports found (8080, 8443, 3306, 5432, etc.)
2. **Fix nmap -O for OS detection:**

   - Add setcap line to kali-tools Dockerfile
   - Re-verify nmap -O works on 149.255.62.131 (accessible IP, not Akamai/CloudFront)
   - Confirm OS findings now appear in reports
3. **Pilot morth.gov.in with new completeness tracking:**

   - Use `platform_finalize_check` to monitor incomplete_profiles count
   - Verify "STRONGLY RECOMMEND CONTINUING" fires when it should
   - Test that OPEN GAPS dedup works correctly on long sessions

### Medium-Term

4. **Severity calibration tightening:**

   - For MEDIUM/HIGH findings, require proof of actual effect, not just "reachable"
   - Spot-check 10% of unexplored assets before categorical dismissal
5. **Service enumeration depth improvements:**

   - Implement parallel `naabu_port_scan` top-10000 on ALL IPs (not just non-Cloudflare)
   - Auto-retry failed full port scans as background jobs
   - Standardize "every port gets a version scan" before considering enumeration done

---

## Key Files Reference

| File                                                               | Purpose                                   | Last Changed                                                           |
| ------------------------------------------------------------------ | ----------------------------------------- | ---------------------------------------------------------------------- |
| `AGENTS.md`                                                      | Operator system prompt (read by OpenCode) | Item 8 rewritten for completeness tracking                             |
| `backend/src/pentest_platform/services/open_loops.py`            | Computes OPEN GAPS + completeness signals | Added host-keyed gaps +`find_incomplete_subdomain_profiles()`        |
| `backend/src/pentest_platform/services/finalize_readiness.py`    | `platform_finalize_check` endpoint      | Wired incomplete_profiles, updated banner text                         |
| `backend/src/pentest_platform/services/parsers/recon_network.py` | Tool output parsing                       | Added OS parser + URL-list digest for gau/wayback/hakrawler            |
| `backend/src/pentest_platform/services/tool_execution.py`        | Execution pipeline                        | Added`_attach_digest()` server-side                                  |
| `platform-mcp/server.py`                                         | MCP server / OpenCode interface           | Updated`_format_exec_result()` to show digest + reduce inline stdout |
| `config/finalize_rules.yaml`                                     | Engagement finalization config            | Has open_gaps dedup settings                                           |
| `pent_reports/civilaviation_report.html`                         | Final assessment (871 lines)              | Shows real depth + honest limitations                                  |

---

## Test Results

- **pytest suite:** 99 passed, same 7 pre-existing unrelated failures, zero regressions (ran 2x after backend restarts)
- **Live verification:**
  - Synthetic 2003-URL gau_discovery test: digest correctly surfaces 3 planted security-interesting URLs
  - Real nmap_service_scan against scanme.nmap.org: `hybrid.digest` populated in HTTP response
  - Subdomain profile completeness: single bare subdomain → incomplete_profile_count=1 and loop appears; five bare subdomains → strongly_recommend_continue fires with full breakdown

---

## How to Use This in Your Next Session

When you start a new conversation with Claude/OpenCode:

1. **Paste this entire document** as context
2. **Reference key points:**
   - "Run morth.gov.in with the new completeness tracking — use `platform_finalize_check` to watch incomplete_profiles"
   - "Don't let full port scans timeout — use `platform_job_start` with timeout=600"
   - "Before dismissing unexplored assets in bulk, spot-check a sample individually"
   - "Verify nmap -O works now (needs Dockerfile fix)"
3. **The platform will automatically:**
   - Track IP/tech/WAF/OS completeness per subdomain
   - Show deduplicated OPEN GAPS (one-liner by default, full on change)
   - Provide per-tool digest to reduce context bloat
   - Fire `⚠ STRONGLY RECOMMEND CONTINUING` when completeness crosses threshold

---

## Session Statistics

- **Time spent:** This session
- **Code changes:** 6 core files modified, 0 regressions
- **Capabilities added:** 3 major (completeness tracking, gaps dedup, context reduction)
- **Test cycles:** 2 full pytest runs, multiple live end-to-end verifications
- **Report generated:** civilaviation.gov.in (824+ findings, 871 lines, identified real gaps + honest limitations)

---

**Ready for next engagement?** Start with morth.gov.in using the completeness tracking. Use `platform_finalize_check` frequently to see what gaps are being tracked. Report back what the full port scan retries find and whether OS detection works post-Dockerfile-fix.
