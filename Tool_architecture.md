# Architecture Blueprint: Autonomous AI Penetration Testing Platform

*Working title: — informed by comparative analysis of HexStrike, Metasploit-MCP, pentestMCP, Shannon, and Darkmoon runs against samaa.tv, plus the tool survey.*

---

## 1. What the comparative data tells us to fix

| Tool | Strength | Core failure mode |
|---|---|---|
| HexStrike | Broadest phase coverage, found `.env` leak | No exploitation follow-through on what it found |
| pentestMCP | Escalated from MCP tools → raw bash when WAF-blocked, found catastrophic DB creds | Only escalated because a human split it into two manual phases — the agent itself didn't decide to pivot |
| Metasploit-MCP | Strong CVE/exploit-framework reasoning | Weak recon breadth — missed 6 defaced subdomains entirely |
| Shannon | Precise, confirmed/unconfirmed labeling, MITRE-mapped | Hard-coded to OWASP checklist (SQLi/XSS/auth) + Claude-only; never noticed the live compromise |
| Darkmoon | Treated subdomains/sister-infra as first-class targets, caught the defacement | No CVSS-rigor, less structured exploitation |

The pattern across all five and the wider survey (NodeZero, XBOW, PentestGPT, Strix, PentAGI, CAI, Shannon) is consistent with what your research doc already names:

- Agents **stall or narrow their scope** the moment a WAF/CAPTCHA/rate-limit shows up, instead of reasoning about alternate paths.
- Multi-step **state/context is lost** over long engagements (pentestMCP needed a manual restart to keep going).
- **Business-logic and cross-asset reasoning** (subdomain → sister-domain → shared-hosting compromise) is the single biggest blind spot — every checklist-driven tool missed the defacement; only the more exploratory one caught it.
- **Failed exploit attempts are ~5x more expensive than successful ones** (per your research) because agents wander down dead ends without a cost-aware planner.
- Exploitation is treated as an afterthought by the recon-heavy tools, and recon is treated as an afterthought by the exploit-heavy tools. Nobody in the sample does both well.

This is the design brief the architecture below answers.

---

## 2. System overview

Four planes, cleanly separated so any LLM can sit in the reasoning plane and any tool can sit in the execution plane:

```
┌─────────────────────────────────────────────────────────────┐
│  PLANNING & REASONING PLANE                                  │
│  Orchestrator · Task-tree planner · Cost-aware scheduler      │
│  Reflection/self-critique loop · LLM-agnostic (BYO model)     │
└───────────────┬────────────────────────────────────────────┘
                │  structured tool calls (MCP)
┌───────────────▼────────────────────────────────────────────┐
│  MEMORY & STATE PLANE                                        │
│  Engagement graph (assets/creds/findings) · Vector recall     │
│  Durable workflow engine (Temporal-style) · Session resume    │
└───────────────┬────────────────────────────────────────────┘
                │
┌───────────────▼────────────────────────────────────────────┐
│  EXECUTION PLANE                                              │
│  Tool-abstraction MCP servers (recon/scan/exploit/post-exploit)│
│  Sandboxed runners (Docker) · Parallel agent workers           │
└───────────────┬────────────────────────────────────────────┘
                │
┌───────────────▼────────────────────────────────────────────┐
│  GOVERNANCE PLANE                                             │
│  Scope engine · Authorization ledger · Rate/impact governor    │
│  Human-approval gates · Audit log · Report/validation engine   │
└─────────────────────────────────────────────────────────────┘
```

The **Governance Plane is not optional bolt-on logging** — it's what makes an autonomous exploitation tool operable at all. Every other plane calls into it before any state-changing action fires.

---

## 3. Planning & Reasoning Plane

### 3.1 Orchestrator = Planner + Critic, not a single ReAct loop

A flat "observe → think → act" loop is exactly what produces the 5x-cost dead-end problem. Instead, run two roles:

- **Planner agent**: maintains a live task tree (à la PentestGPT) — `Recon → [Subdomain Enum, Sister-Domain Discovery, DNS/IP] → Service Enum → Vuln Scan → Exploitation → Post-Ex → Reporting`, with branches spawned dynamically as findings come in (e.g., discovering shared hosting on one subdomain spawns a "check sibling subdomains on same IP" branch — this is precisely what would have caught the samaa.tv defacement automatically instead of by luck).
- **Critic agent**: before committing budget to a branch, scores it on expected-value vs. cost (time, requests, LLM tokens) using signals like: prior success rate of this technique class, WAF/rate-limit signals seen so far, asset criticality. Branches that look like dead ends get pruned early instead of exhausted — this is the direct fix for the cost asymmetry your research flagged.

### 3.2 Escalation logic (fixes the pentestMCP failure mode)

Encode "when tool X is blocked, try Y" as **first-class planner state**, not a manual restart:

```
IF (tool_call.result == BLOCKED_BY_WAF | TIMEOUT | RATE_LIMITED):
    log_signal(target, technique, blocked=True)
    consult_escalation_matrix(technique)
        → alternate tool (e.g., MCP wrapper fails → raw curl/python)
        → alternate path (e.g., /wp-json/ blocked → /index.php/wp-json/, as Darkmoon found manually)
        → alternate vector (e.g., app-layer blocked → check sibling subdomain on same host)
    IF no alternate found: mark branch exhausted, surface to Critic for re-prioritization
```

This escalation matrix is a first-class configuration artifact you maintain and grow — it's effectively where your team's pentesting expertise gets encoded, and it's the actual differentiator over "LLM + tool list" tools.

### 3.3 Reflection loop

After each phase, a lightweight self-critique pass compares findings against expected coverage for the asset type (e.g., "we fingerprinted Laravel — did we check `.env`, debug mode, Ignition RCE, session cookie scope, APP_KEY exposure?") so checklist coverage isn't purely emergent from the LLM's mood. This is how you get HexStrike's breadth without hardcoding Shannon's rigidity.

---

## 4. Memory & State Plane

This is the plane most existing tools skip, and it's why long engagements degrade.

- **Engagement graph**: a typed graph store (assets, IPs, subdomains, credentials, technologies, findings, relationships like `hosted_on`, `shares_cookie_domain_with`, `same_org_as`). Sister-domain discovery (`nust.edu.pk` ↔ `seecs.edu.pk`) is a graph-traversal query over this store fed by WHOIS org fields, shared ASN, shared analytics/tracking IDs, cert SANs, and shared nameservers — not a one-off script.
- **Durable workflow engine**: use something like Temporal (Shannon's approach is worth borrowing) so a 6-hour engagement survives crashes, API rate limits, or a switched LLM backend mid-run without losing state — directly fixes the "agents lose context over long multi-step sequences" weakness in your research notes.
- **Credential/session vault**: anything harvested (leaked `.env` creds, session tokens, API keys) gets stored structurally and is queryable by later phases — this is what turns "found a leaked password" into "used it to pivot," which is the exploitation gap every report here has.

---

## 5. Execution Plane — tool abstraction via MCP

Structure MCP servers by **capability domain**, not by underlying tool, so swapping Nmap for Rustscan or sqlmap for Ghauri doesn't touch the planner:

- `recon.mcp` — WHOIS, DNS (dig/subfinder/amass), sister-domain heuristics, tech fingerprinting, OSINT (theHarvester-class), archive/Wayback checks (Darkmoon used this well)
- `network.mcp` — port scan, service/version enum, TLS/cert inspection
- `webapp.mcp` — directory/vhost busting, param discovery (Arjun-class), header/config auditing, CMS-specific enum (wp-json etc.)
- `vuln.mcp` — nuclei-style template scanning, CVE correlation against fingerprinted versions, SQLi/XSS/SSRF probing
- `exploit.mcp` — Metasploit RPC integration, exploit-db/searchsploit lookups, custom PoC runner — **gated by the Governance Plane, always**
- `postex.mcp` — credential/artifact collection *within the already-compromised host*, lateral-movement enumeration (BloodHound-style graph queries), persistence *detection* for reporting purposes
- `report.mcp` — structured finding schema → CVSS scoring → PoC evidence bundling → HTML/PDF generation (all five sample reports show a workable schema to converge on)

LLM-agnosticism (unlike Shannon's Claude lock-in) comes for free here because the planner only ever emits structured tool calls — swap the model behind the Planner/Critic roles without touching execution.

---

## 6. On CAPTCHA/OTP and hard perimeter controls — a scoping note, not a technical one

Worth being direct about this since it's explicitly a differentiator you want: I'd draw the line at **automated defeat of third-party anti-automation controls (Cloudflare Turnstile, hCaptcha, OTP/2FA) as a built-in agent capability**, for reasons that are more about engagement validity than tooling difficulty:

- Bypassing Cloudflare's own challenge is attacking Cloudflare's infrastructure, not your client's — your client's authorization doesn't cover that, even in a full-scope engagement.
- Automated OTP defeat almost always means either (a) SIM/email account compromise (out of technical scope for a web pentest tool) or (b) brute-forcing a 2FA code, which is a rate-limiting/entropy finding you *report*, not bypass and continue past.
- What actually gets AI pentesters "stuck" here in practice is usually solvable without touching the CAPTCHA at all: negotiate a **client-provided bypass token / IP allowlist for the testing window** (standard in real engagements), test the **API/mobile-app path** that often skips the same CAPTCHA the web login has, or simply **report the control as evidence it's working** and move the engagement budget to unauthenticated attack surface instead.

Architecturally: build a `perimeter_control_detected` signal that the Planner treats like the WAF-block signal in §3.2 — log it, check the scope agreement for a client-provided bypass, and if none exists, deprioritize that branch and reallocate budget rather than trying to defeat it. That's a better product decision anyway — "we detected and correctly triaged a CAPTCHA-protected endpoint" is a stronger report line than a fragile bypass hack.

---

## 7. Exploitation & post-exploitation — design, not payloads

Exploitation is your stated differentiator, so it needs real structure, but I'm keeping this at the architecture level rather than writing exploit logic:

- **Finding → exploit mapping**: every vuln-scan finding carries a structured type (CWE/CVE/technique class). The exploit planner matches this against a capability registry (Metasploit modules, known PoC patterns, custom scripts) and proposes a ranked list of exploitation attempts with expected impact and blast radius.
- **Impact-tiered approval gates**: read-only confirmation (e.g., confirm SQLi with a boolean-blind check) auto-proceeds; anything with a write/destructive/persistence effect (dropping a webshell, creating an AD account, modifying data) requires a human-approval gate by default, configurable per engagement's rules of engagement. NodeZero/XBOW-style "fully autonomous" is a config toggle for engagements that explicitly authorize it, not the default.
- **Post-exploitation** should be framed as **evidence collection under authorization**: credential harvesting from an already-compromised host, mapping lateral-movement *paths* (not necessarily executing all of them), and privilege-escalation detection — enough to prove impact for the report, with a defined stop condition (e.g., "prove domain admin is reachable" rather than "actually take every AD box down").
- **Cleanup/rollback log**: every state-changing action gets an entry in a rollback ledger (webshells dropped, accounts created, files modified) so post-engagement cleanup is a deterministic replay, not a memory exercise. This is standard professional practice and it's the kind of thing that separates a real pentesting product from a toy.

---

## 8. Governance Plane (this is what makes autonomy safe to sell)

- **Scope engine**: engagement config defines in-scope domains/IPs/CIDR ranges, excluded techniques (e.g., no DoS, no social engineering), time windows, and approval requirements. Every tool call is checked against this before execution — not logged after the fact.
- **Authorization ledger**: signed engagement contract reference attached to every action in the audit log; this is your legal defensibility layer.
- **Rate/impact governor**: global and per-target request-rate caps, automatic backoff on 5xx spikes (don't be the tool that DoSes a production news site), circuit breaker on repeated destructive-action failures.
- **Audit log**: full command + response trail, independent of the LLM's own reasoning trace, so a human can reconstruct exactly what happened without trusting the model's self-report.

---

## 9. Reporting engine

Converge the five schemas you already have data on into one structured finding format:

```
finding: {
  id, title, severity, cvss_vector, cwe, mitre_attack_id,
  status: confirmed | unconfirmed,       # borrow from Shannon
  endpoint, discovered_by_agent, evidence: {commands, raw_output, screenshots},
  exploited: bool, exploitation_evidence,  # your differentiator vs. all 5 samples
  impact, remediation, references
}
```

Validation rule before a finding is marked `confirmed`: it must have either a reproducible PoC command+response pair, or (for exploitation-class findings) actual working exploitation evidence — this is the XBOW/Strix "no theoretical findings" principle, and it's what stops the false-positive noise your research flags as a common failure of open agentic tools.

---

## 10. Suggested build order (MVP → full platform)

1. **Governance + Memory plane first.** Boring, but everything else depends on scope enforcement and the engagement graph existing before agents run wild.
2. **Recon + sister-domain graph reasoning.** This is cheap to build and is exactly the gap that made Darkmoon outperform the checklist tools — high leverage for low engineering cost.
3. **Planner/Critic loop with escalation matrix**, running against read-only recon/scan MCP servers only (no exploitation yet) — validate the cost-aware branch pruning against real budgets before you let it touch exploitation.
4. **Vuln-scan + CVE correlation MCP**, with the confirmed/unconfirmed validation discipline from day one.
5. **Exploitation MCP with impact-tiered approval gates**, starting with auto-approved read-only confirmations only; graduate to higher-impact actions per engagement config.
6. **Post-exploitation + reporting engine.**
7. **LLM-agnostic swap-test** — run the same engagement against two different backend models to confirm the architecture is actually model-agnostic and not secretly coupled to one vendor's tool-calling quirks (Shannon's mistake).

---

## 11. Where this beats the five reference tools directly

- vs. **HexStrike**: keeps its phase breadth, adds exploitation follow-through via the impact-tiered exploit planner.
- vs. **pentestMCP**: the escalation matrix makes tool-fallback (MCP → raw request) an automatic planner decision, not a manual restart.
- vs. **Metasploit-MCP**: recon-first graph reasoning (sister/subdomain discovery) closes the "missed 6 defaced subdomains" gap.
- vs. **Shannon**: keeps its confirmed/unconfirmed rigor and MITRE mapping, drops the hardcoded checklist and single-vendor lock-in.
- vs. **Darkmoon**: keeps the exploratory cross-asset reasoning, adds the CVSS/validation discipline it was missing.
