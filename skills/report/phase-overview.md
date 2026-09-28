---
name: report-overview
description: "Reporting methodology: turn platform_report_outline/platform_report_data's structured payload into a professional deliverable — executive summary, impact-first findings, prioritized remediation. Summarize from engagement memory, never from chat reconstruction; not a mandatory stage."
phases: [report]
tags: [report, overview, remediation]
---

# Reporting methodology

The platform gives you the data; writing the report well is your job, and it's where a
pentest is actually judged — a technically excellent engagement with a mediocre report reads,
to the client, as a mediocre engagement. Two tools do the heavy lifting; don't reconstruct from
chat scrollback, and don't skip either:

- **`platform_report_outline`** — the honesty scaffold: Confirmed / Likely / Hypotheses, plus
  conductor phase status. This is Osprey's actual differentiator — most scanner output reads as
  "confirmed" whether it was reproduced or just detected; you have the real distinction stored,
  so *use it in the prose*, not just internally. A reader should be able to tell, per finding,
  whether it was proven or suspected.
- **`platform_report_data`** — the quantitative payload: severity breakdown, counts, findings
  by severity, infrastructure notes, Mermaid topology. This is what an executive summary's
  numbers and the topology diagram come from — don't hand-count from `platform_findings`.

## Structure (what a real client-facing report needs, in order)

1. **Executive summary** — 3-6 sentences, for someone who will never open the technical
   section. State the overall risk posture, the count of Confirmed CRITICAL/HIGH findings (not
   total findings — a pile of INFO-grade noise inflates the number and dilutes the ones that
   matter), and the single biggest risk in one sentence a non-technical reader acts on. Never
   lead with tool names or CVE ids here.
2. **Scope & methodology** — what was tested, what wasn't (explicitly — an unstated exclusion
   reads as an oversight later), and the RoE that applied (`allow_exploitation`,
   `destructive_actions_allowed` as configured). One paragraph, not a tool inventory.
3. **Findings, grouped by severity then by asset** — not by the tool that found them, not in
   discovery order. Each finding gets:
   - **Impact first, mechanism second.** "An unauthenticated attacker can read any user's
     order history" beats "IDOR on `/api/orders/{id}`" as the opening sentence — the mechanism
     belongs in the next sentence, for the reader who wants it.
   - **Confidence stated in plain language, not just a badge** — "confirmed by replaying the
     request as a second account" (CONFIRMED) reads completely differently from "flagged by an
     automated scan, not independently reproduced" (HYPOTHESIS/LIKELY) — say which, every time.
     A report that quietly treats both the same is the exact failure mode the evidence law
     exists to prevent; don't undo that discipline in the prose.
   - **Evidence, not a claim** — the excerpt `evidence_grounding.py` already required to exist
     for a REPRODUCTION-graded finding is what goes in the report's evidence block, verbatim or
     lightly redacted (mask a real secret value; never mask *that* one existed).
4. **Remediation, prioritized by (exploitability × business impact), not by CVSS alone** — a
   MEDIUM-CVSS bug on the public login page with a confirmed PoC outranks a CRITICAL-CVSS bug on
   an internal admin panel nobody could reach without another vuln first. Group remediation
   items that share a root cause (three IDORs from the same missing authorization middleware
   layer are one fix, not three tickets) — this is often the single most useful thing a report
   does that a raw finding list doesn't.
5. **Technical appendix** — the tool-by-tool detail, full requests/responses, for the engineers
   who'll actually fix it. This is where `build_recon_markdown`-shaped detail belongs; it's not
   the report's front matter.

## Do not

- Report a HYPOTHESIS-confidence item in language indistinguishable from a CONFIRMED one — the
  entire evidence-grading system exists so this platform doesn't repeat the "scanner detection
  became a confirmed finding" failure mode; a sloppy report can still reintroduce it in prose
  even when the underlying data is honest.
- Pad the finding count with informational/none-severity items to look thorough — a report a
  client can't act on because the signal is buried in noise is worse than a shorter one.
- Invent a remediation you haven't verified is actually available for that stack/version — check
  the vendor's real advisory/changelog before recommending a specific patch version.
