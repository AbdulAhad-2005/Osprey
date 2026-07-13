# Network Phase

Goal: discover open ports and services on hosts confirmed during recon.

**Workflow (suggested):**
1. Fast port discovery (`rustscan_fast_scan` or `masscan_high_speed`)
2. Service/version enumeration on open ports (`nmap_service_scan`)
3. Protocol-specific follow-up (SMB → enum4linux, etc.)

**Safety:** Respect governance — some tools require approval or are blocked on production targets.

**Flags:** Always allowed via `additional_args` unless they contain shell metacharacters (`;|&`$()<>`).
