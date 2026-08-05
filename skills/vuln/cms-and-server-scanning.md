# CMS & web-server vulnerability scanning

Two high-yield, low-effort scans once recon has fingerprinted a web host: `nikto_scan` for the
server layer and `wpscan_analyze` when the app is WordPress.

## nikto — web-server misconfiguration

`nikto_scan` (target= URL/host) checks the server for dangerous files, default/sample pages,
dated software, missing security headers, exposed backups, and known-bad paths.

- Run on every live web host as a cheap baseline. It's noisy and slow-ish — batch it via
  `platform_job_start`.
- Findings are parsed from its `+ ` lines into `vulnerability` findings. Most are LOW/INFO
  config issues (still reportable — missing headers, directory indexing); the disclosure and
  outdated-software items are the ones to chase.
- A WAF will mangle nikto badly (floods of 403s). If recon flagged a WAF, expect noise and
  prefer targeted nuclei templates instead.

## wpscan — WordPress

WordPress powers a large share of the web and its **plugins/themes** are where most CVEs live.
When `whatweb`/`tech_stack_analyze` flags WordPress, run `wpscan_analyze` (url=).

- It enumerates core version, plugins, themes, users, and interesting files, and maps each
  component to known vulnerabilities. Output is JSON, parsed into `vulnerability` findings with
  CVEs and `fixed_in` versions.
- **Vuln data needs the API token** — without `--api-token <token>` (pass via additional_args)
  wpscan enumerates components but returns limited CVE detail. Note in the finding when data was
  token-limited.
- Enumerate more aggressively with `--enumerate ap,at,u` (all plugins/themes/users) via
  additional_args when scope allows; the default passive enumeration misses inactive plugins.

## Reading results

- A wpscan "vulnerable version" is **present-but-verify**: confirm the *running* version is in
  the affected range (wpscan sometimes flags by presence, not confirmed version). Default MEDIUM
  until the version is pinned.
- nikto/wpscan `interesting_findings` (readme, debug log, exposed `wp-config` backup) are
  OBSERVED information-disclosure leads — fetch to confirm real content.

## Do not

- Run wpscan on a non-WordPress host — wasted turns. Gate it on the WordPress tech signal.
- Trust plugin-version CVE mapping as exploitable without confirming the version and that the
  vulnerable code path is reachable.
- Brute-force users/logins here — that's credential attack / exploitation, needs approval.
