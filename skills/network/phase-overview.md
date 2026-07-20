# Network Phase

Goal: discover open ports and services on hosts/IPs confirmed during recon.

**Workflow (suggested, not mandatory):**
1. Read **network surface** / gaps: which IPs have `ports_known=false`
2. Fast port discovery per those IPs (`nmap_syn_scan` / `rustscan_fast_scan`)
3. Where `ports_known` but not `services_known` → optional `nmap_service_scan`
4. Protocol-specific follow-up (SMB on 445/139, etc.)

**Next step:** Prefer soft `ip_unscanned` / `ip_ports_no_service_scan` gaps over rescanning everything.

**Safety:** Respect governance. Never `-p-` / `1-65535` unless the user allows.

**Flags:** Allowed via `additional_args` unless they contain shell metacharacters.
