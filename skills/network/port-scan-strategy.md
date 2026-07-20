# Port Scan Strategy

**When:** You have a host IP or hostname from recon findings.

**Fast discovery:** `rustscan_fast_scan` — use `additional_args` for batch size, ulimit, or `-- -A` passthrough to nmap.

**Wide sweeps:** `masscan_high_speed` with rate limits in `additional_args` (e.g. `--rate 1000`).

**Stealth / full TCP:** `nmap_syn_scan` with `ports`, `timing`, and any nmap flags in `additional_args` or `flags` for custom scans.

**Custom nmap:** `nmap_custom_scan` — put the full flag string in `flags` or `additional_args`.

**Pivot:** Open 445/139 → SMB enumeration task. Open 80/443 → return to web recon if not done.

## Context-dependent scanning
Read CURRENT SITUATION before each tool. Do not run SMB tools without 139/445 in evidence.
Use targeted port lists from findings when a wide scan already failed or timed out.
The container is unprivileged — prefer `-sT` / `--unprivileged` over raw SYN, and `-Pn` when a host blocks ping.
