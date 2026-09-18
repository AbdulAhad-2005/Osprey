---
name: quickscan
description: Bind a target and run a fast recon sweep. Usage: /quickscan <domain-or-ip>
---
Bind the target $ARGUMENTS and run a fast recon sweep: subdomain enumeration
(subfinder + crt.sh), resolve to IPs, probe live hosts (httpx), a top-ports scan,
and service/version detection on anything open. Report the live surface concisely
with evidence, then tell me what looks most worth digging into.
