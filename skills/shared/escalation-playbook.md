# Escalation Playbook (Recon + Network)

When a tool fails, times out, returns thin results, or hits a WAF — **do not stop**. Consult escalations before marking a branch exhausted.

## Signals

| Signal | Meaning |
|--------|---------|
| `waf_block` | 403, Cloudflare, access denied |
| `rate_limit` | Too many requests |
| `timeout` | Scan or probe timed out |
| `few_results` | Success but < 5 lines of useful output |

## Recon patterns
- **WAF on /** → retry with `/index.php/` path on httpx
- **Few subdomains** → amass `-passive`, then fierce, then dnsenum
- **Shared IP siblings** → probe all hosts on same IP (defacement check)

## Network patterns
- **rustscan filtered** → masscan with `--rate 1000`, then nmap `-Pn`
- **445 open** → enum4linux → smbmap → netexec
- **Ports without versions** → nmap_service_scan on discovered port list

## LLM freedom
Escalations suggest tools and example `additional_args`. You may use **any valid flags** beyond examples.
