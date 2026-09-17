---
name: verification-and-severity
description: "Severity discipline: severity reflects proven impact, not a scanner pattern-match; confidence states how sure we are. Verify before rating so reports are not a wall of unverified criticals."
phases: [vuln]
tags: [vuln, severity, verification]
---

# Verification & severity discipline

The fastest way to make a report worthless is a wall of scanner "detections" rated critical as
if they were proven exploits. Severity is earned from evidence. There is no platform clamp doing
this for you anymore — you own both the severity and the confidence of every finding, honestly,
every time.

## Two independent things you assign: severity and confidence

- `claim_severity` (INFO → CRITICAL): impact **if the finding is real**.
- `confidence` (CONFIRMED / LIKELY / HYPOTHESIS): how sure we are it's real.

These do not clamp each other automatically. That is exactly why you have to think about both,
every time, instead of trusting a tool's own verdict:

| What actually happened | Severity ceiling | Confidence |
|---|---|---|
| A tool merely detected a pattern — sqlmap says "the parameter appears injectable" with no `--dump`, a nuclei template matched, a version sits in a vulnerable range, wpscan flagged a plugin CVE by version | **HIGH**, never CRITICAL | `LIKELY` |
| Exploitation actually proven — real rows extracted, a shell obtained and a command executed with captured output, a credential tested and accepted by the live service, a file actually read | may reach `CRITICAL` | `CONFIRMED` |
| A passive/soft lead — DNS/CT signal, sister domain, name collision, a CVE only implied by a banner | `LOW`/`INFO` | `HYPOTHESIS` unless corroborated |

## Turning a detection into proof

1. **Escalate the tool** — `sqlmap --dump`/`--os-shell`, `dalfox --verify`, an actual exploit
   attempt — rather than accepting the first "vulnerable" verdict as the finding.
2. **Capture the artifact** — the extracted rows, the shell banner and command output, the
   accepted-credential response — as the evidence, not the scanner's own claim about itself.
3. Only then does the finding become CRITICAL/CONFIRMED. Until you have that artifact, it stays
   HIGH/LIKELY at most, titled as a detection, and belongs in the exploit-attempt queue — not a
   "proven" section of the report.

## Writing the finding

- **Title states proof status honestly**, e.g. "SQL injection detected — not yet exploited" vs.
  "SQL injection — confirmed, 22 tables extracted." Never let the title imply more than the
  evidence backs.
- **Evidence** = the reproducing request/response for a detection, or the actual extracted
  data/shell output for a CONFIRMED claim.
- **Severity and confidence are each earned on their own** — a CONFIRMED classification doesn't
  retroactively justify a higher severity than the impact warrants, and a CRITICAL impact doesn't
  borrow credibility from thin confidence.
- Note false-positive risk explicitly when unverified ("flagged by version; exploit path
  unconfirmed").

## Do not

- Copy a scanner's own severity/confidence verbatim onto an unverified match — nuclei, sqlmap,
  and wpscan all report generously by design; you own the honest label, not the tool.
- Write "confirmed" or "exploited" for a pattern match. Confirmed means you hold the artifact
  that proves it, not that a tool said so.
- Claim impact you didn't observe. "Vulnerable version present" ≠ "exploitable." "Scanner says
  vulnerable" ≠ "exploited."
- Bury a genuinely proven critical under a wall of unverified detections rated the same way —
  rank by proof, not by what the tool's own output claims.
