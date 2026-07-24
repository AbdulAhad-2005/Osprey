# Escalation Playbook (Recon + Network)

When a tool fails, times out, returns thin results, or hits a WAF — **do not stop**. Consult escalations before marking a branch exhausted.

## Signals

| Signal | Meaning |
|--------|---------|
| `waf_block` | 403, Cloudflare, access denied |
| `rate_limit` | Too many requests |
| `timeout` | Scan or probe timed out |
| `few_results` | Success but < 5 lines of useful output |
| `missing_api_key` | Shodan/other keyed tool unavailable |

## Recon patterns
- **WAF on /** → retry with `/index.php/` path on httpx
- **Few subdomains** → amass `-passive`, then fierce, then dnsenum, then `crt_sh_query`
- **Still thin** → `shodan_search` (`hostname:` / `ssl:` / `org:`) if key present
- **Shared IP siblings** → probe all hosts on same IP (defacement check) — don't assume they're
  identical just because the IP matches; each still needs its own pass
- **SaaS-looking CNAMEs** → `subdomain_takeover_check` on the list
- **httpx_probe / dnsx_resolve error on a large target list** → split into smaller batches
  (10-15 hosts) and retry each; don't drop the batch and move on

## Network patterns
- **naabu thin/fail** → rustscan, then masscan `--rate 1000`, then nmap `-Pn`
- **445 open** → enum4linux → smbmap → netexec
- **Ports without versions** → nmap_service_scan on discovered port list
- **Shodan suggested ports** → verify with naabu/nmap on that shortlist first

## LLM freedom
Escalations suggest tools and example `additional_args`. You may use **any valid flags** beyond examples.
