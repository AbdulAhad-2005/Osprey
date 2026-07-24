# Subdomain Enumeration

**When:** Start of recon on a single root domain.

**Default:** `subfinder_scan` with `domain` param.

**Pivot rules:**
- Few results → try `amass_scan` with `additional_args: "-passive"` or `fierce_scan`
- Need brute force → `amass_scan` with `additional_args: "-brute -w /path/to/wordlist"` (any valid amass flags)
- DNS-focused → `dnsenum_scan`
- CT gap-fill → `crt_sh_query`
- Passive internet view → `shodan_search` with `domain=` or `query=hostname:…` / `ssl:…`
- After a solid host list → `subdomain_takeover_check` (`mode=list`) on interesting names

**Params:** `domain` (required for most). Pass any extra flags in `additional_args` — not limited to documented examples.

**Do not:** Run intrusive scans before passive sources are exhausted unless engagement rules allow it.
