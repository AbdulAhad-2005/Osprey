# Attack-surface instincts (ideas, not a script)

Elite means: use the **resources you have** (typed tools, domain_hunter, amass,
jobs, fanout, scripts) to build the best picture — not stop after the first
comfortable tool result.

This is how a strong operator *thinks* when a domain lands. Reorder, skip, or
invent when evidence says so. Do **not** treat this as autopilot stages.

## Expansion instincts

1. **Seed** — org/whois context; clarify affiliate scope if unclear.
2. **Widen names** — subdomains *and* sister/affiliate roots (`domain_hunter`)
   early; one passive enum is not “done” (amass/crt.sh when inventory looks thin).
3. **Live alongside enum** — as names appear, probe HTTP(S) in parallel
   (`httpx_probe`, `platform_fanout_assets`, `platform_job_start`) — don’t wait
   for a perfect list.
4. **IP / edge map** — resolve → group by IP; CDN/WAF/firewall vs origin-looking.
5. **Ports / services** — on IPs worth time: fast discovery → version on interesting
   opens; if one scanner fails, **fallback** (masscan/nmap/script), don’t stop.
6. **Footprint** — banners, tech, emails/creds only when observed; on live web:
   stack, interesting paths/URLs, crawl high-value apps.
7. **Invent** — catalog missing custom app work → `platform_script` (+ FINDING lines).
8. **Deepen** — crown jewels / confirmed roles get app depth; then grades + finalize.

## Anti-patterns (why sessions go flat)

- Subfinder once → httpx once → “ports filtered” → report. That is incomplete thinking.
- Skipping `domain_hunter` / second enum / jobs / scripts because “enough for chat.”
- Treating advisory gaps as optional noise instead of unanswered questions.
- Giving up after one tool error (HTTP 500, rustscan syntax) without TRY NEXT.

## Parallelism default

Long scans → background jobs. Batch hosts → fanout_assets. Keep 0–4 job slots busy
when the surface is growing. Narrate branches in chat.
