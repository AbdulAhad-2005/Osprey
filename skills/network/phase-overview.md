# Network Phase

Goal: discover ports and services on hosts/IPs already in recon memory — do not
re-enumerate subdomains here unless a new IP sibling appears.

**Instincts:**
1. Prefer IPs/hostnames already in the graph; group by shared IP when useful
2. Fast port discovery first (`naabu_port_scan`, else rustscan/masscan/nmap)
3. Version/scripts on interesting opens (`nmap_service_scan`) — not every port
4. Protocol follow-up only when evidence supports it (e.g. 445 → SMB tools)
5. If a scanner fails or times out: shrink scope / change tool — don’t “fix” by
   widening to full-range without asking the human

**Passive assist:** Shodan host/search results may suggest ports; still verify live
before SMB/web pivots.

**Output:** Ports, services, and protocol observations into platform memory.
